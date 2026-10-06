import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import main
from token_security import TokenSecurity, DEFAULT_SETTINGS
from non_evm_security import SPL2022, solana_native, solana_scanner
from test_security import CA, clean_goplus
import test_security as baseline
from test_multichain import MINT, native_solana, gp_solana


class EvidencePolicyTest(unittest.TestCase):
    def test_llama_three_percent_and_modifiable_fees_are_advisories(self):
        data = native_solana(SPL2022)
        data['value']['data']['parsed']['info']['extensions'] = [{
            'extension': 'transferFeeConfig', 'state': {
                'transferFeeConfigAuthority': 'active',
                'olderTransferFee': {'transferFeeBasisPoints': 300},
                'newerTransferFee': {'transferFeeBasisPoints': 300}}}]
        b, u, w = solana_native(data, DEFAULT_SETTINGS)
        self.assertFalse(b); self.assertFalse(u)
        self.assertIn('Solana: commissioni modificabili', w)
        self.assertTrue(any('3%' in item for item in w))
        self.assertTrue(solana_native(data, {**DEFAULT_SETTINGS, 'security_mode': 'strict'})[0])
        for field in ('olderTransferFee', 'newerTransferFee'):
            state = data['value']['data']['parsed']['info']['extensions'][0]['state']
            state[field]['transferFeeBasisPoints'] = 1100
            self.assertTrue(solana_native(data, DEFAULT_SETTINGS)[0])
            state[field]['transferFeeBasisPoints'] = 300

    def test_scanner_fractional_fee_requires_native_confirmation(self):
        data = gp_solana()
        data['transfer_fee'] = {'current_fee_rate': {'fee_rate': '0.03'},
                                'scheduled_fee_rate': [{'fee_rate': '0.03'}]}
        b, u, w = solana_scanner(data, DEFAULT_SETTINGS)
        self.assertFalse(b); self.assertTrue(u); self.assertTrue(w)

    def test_actual_frozen_default_and_active_pause_block_but_capabilities_warn(self):
        data = native_solana(SPL2022)
        info = data['value']['data']['parsed']['info']
        for ext in [{'extension': 'defaultAccountState', 'state': {'accountState': 'frozen'}},
                    {'extension': 'pausableConfig', 'state': {'paused': True}}]:
            info['extensions'] = [ext]
            self.assertTrue(solana_native(data, DEFAULT_SETTINGS)[0])
        info['extensions'] = [{'extension': 'pausableConfig', 'state': {'paused': False}}]
        self.assertFalse(solana_native(data, DEFAULT_SETTINGS)[0])
        self.assertTrue(solana_native(data, DEFAULT_SETTINGS)[2])

    def test_identification_rejects_substrings_and_preserves_sui_case(self):
        for address, kind in [(CA, 'evm'), (MINT, 'solana'), ('0x2::sui::SUI', 'sui')]:
            self.assertEqual(main.identify_token(address), kind)
        for address in ('not a token', 'text ' + CA, CA + 'z'):
            with self.assertRaises(ValueError): main.identify_token(address)

    def test_requested_preset_is_applied_once_without_erasing_history(self):
        with tempfile.TemporaryDirectory() as folder:
            db = main.open_db(str(Path(folder) / 'db'))
            main.setting_set(db, 'forward_delay_seconds', '2')
            main.setting_set(db, 'source_chat', '@keep')
            main.mark_forwarded(db, 'evm', CA)
            main.migrate_evidence_policy(db)
            self.assertEqual(main.setting_get(db, 'forward_delay_seconds', ''), '1')
            self.assertEqual(main.setting_get(db, 'security_timeout_seconds', ''), '2.5')
            self.assertEqual(main.setting_get(db, 'source_chat', ''), '@keep')
            self.assertTrue(main.is_forwarded(db, CA))
            main.setting_set(db, 'forward_delay_seconds', '0.5')
            main.migrate_evidence_policy(db)
            self.assertEqual(main.setting_get(db, 'forward_delay_seconds', ''), '0.5')
            db.close()


class EvidenceAsyncTest(unittest.IsolatedAsyncioTestCase):
    async def test_capabilities_and_missing_core_fields_pass_with_warnings(self):
        guard = TokenSecurity(); token = clean_goplus()
        token.update(is_blacklisted='1', transfer_pausable='1', is_proxy='1', owner_change_balance='1')
        token.pop('is_honeypot')
        async def get(session, url, params=None):
            return {'code': 1, 'result': {CA: token}} if 'goplus' in url else {'pairs': []}
        with patch.object(guard, '_get', side_effect=get):
            r = await guard.check('evm', CA, {**DEFAULT_SETTINGS, 'security_chain': '56'})
        self.assertEqual(r.verdict, 'allowed_with_warnings'); self.assertTrue(r.warnings)

    async def test_evm_known_honeypot_survives_other_network_timeout(self):
        guard = TokenSecurity(); token = clean_goplus(); token['is_honeypot'] = '1'
        async def get(session, url, params=None):
            if url.endswith('/56'): return {'code': 1, 'result': {CA: token}}
            await asyncio.sleep(10)
        start = time.monotonic()
        with patch.object(guard, '_get', side_effect=get):
            r = await guard.check('evm', CA, DEFAULT_SETTINGS)
        self.assertEqual(r.verdict, 'blocked'); self.assertLess(time.monotonic() - start, .5)

    async def test_ambiguous_evm_identity_is_not_automatically_forwarded(self):
        guard = TokenSecurity()
        async def get(session, url, params=None):
            return {'code': 1, 'result': {CA: clean_goplus()}} if 'goplus' in url else {'pairs': []}
        with patch.object(guard, '_get', side_effect=get):
            r = await guard.check('evm', CA, DEFAULT_SETTINGS)
        self.assertFalse(r.allowed); self.assertTrue(r.checks['identity_error'])

    async def test_strict_timeout_stays_closed(self):
        guard = TokenSecurity()
        async def slow(*args): await asyncio.sleep(10)
        with patch.object(guard, '_get', side_effect=slow), patch.object(guard, '_rpc', side_effect=slow):
            r = await guard.check('solana', MINT, {**DEFAULT_SETTINGS, 'security_mode': 'strict', 'security_timeout_seconds': 1})
        self.assertFalse(r.allowed)


class EvidenceBotTest(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = baseline.BotIntegrationTest.asyncSetUp
    asyncTearDown = baseline.BotIntegrationTest.asyncTearDown
    event = baseline.BotIntegrationTest.event
    history = baseline.BotIntegrationTest.history
    config = baseline.BotIntegrationTest.config

    async def test_manual_check_auto_detects_without_sending(self):
        from token_security import SecurityResult
        checker = AsyncMock(return_value=SecurityResult('allowed_with_warnings', ['checked'], chain_id='solana'))
        with patch.object(TokenSecurity, 'check', new=checker):
            async with self.http.post(self.url + '/api/security/check', json={'address': MINT}) as r:
                self.assertEqual(r.status, 200); self.assertEqual((await r.json())['kind'], 'solana')
        self.assertEqual(checker.await_args.args[0], 'solana')
        self.assertEqual(self.client.attempts, 0)

    async def test_delay_overlaps_screening_instead_of_adding(self):
        from token_security import SecurityResult
        await self.config(forward_delay_seconds=1)
        async def check(*args):
            await asyncio.sleep(.6)
            return SecurityResult('allowed', ['checked'])
        start = time.monotonic()
        with patch.object(TokenSecurity, 'check', new=AsyncMock(side_effect=check)):
            await self.event()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 1); self.assertLess(elapsed, 1.45)
        self.assertEqual(self.client.sent, [(202, CA)])
