import asyncio
import copy
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import main
from token_security import DEFAULT_SETTINGS, TokenSecurity, SecurityResult
from non_evm_security import (SPL, SPL2022, canonical_sui, solana_scanner,
                              solana_native, sui_scanner, resolve_sui)
import test_security as baseline
from test_security import CA, clean_goplus

MINT = "So11111111111111111111111111111111111111112"
COIN = "0x2::sui::SUI"


def gp_solana():
    return {**{k: {"status": "0", "authority": []} for k in
        ("freezable", "balance_mutable_authority", "closable", "default_account_state_upgradable",
         "transfer_fee_upgradable", "transfer_hook_upgradable", "mintable", "metadata_mutable")},
        "default_account_state": "1", "non_transferable": "0", "transfer_hook": [], "transfer_fee": {}}


def native_solana(program=SPL):
    return {"value": {"owner": program, "executable": False, "data": {"parsed": {
        "type": "mint", "info": {"isInitialized": True, "freezeAuthority": None,
        "mintAuthority": None, "extensions": []}}}}}


def gp_sui():
    return {k: {"value": "0", "cap_owner": "Immutable"} for k in
            ("blacklist", "mintable", "contract_upgradeable", "metadata_modifiable")}


class NativeRulesTest(unittest.TestCase):
    def test_solana_concrete_restrictions_block(self):
        for key in ("freezable", "balance_mutable_authority", "closable", "default_account_state_upgradable", "transfer_fee_upgradable", "transfer_hook_upgradable"):
            data = gp_solana(); data[key]["status"] = "1"
            if key == "freezable":
                self.assertTrue(solana_scanner(data, DEFAULT_SETTINGS)[0], key)
            else:
                self.assertFalse(solana_scanner(data, DEFAULT_SETTINGS)[0], key)
                self.assertTrue(solana_scanner(data, DEFAULT_SETTINGS)[2], key)
            self.assertTrue(solana_scanner(data, {**DEFAULT_SETTINGS, "security_mode": "strict"})[0], key)
        data = gp_solana(); data["transfer_hook"] = [{"address": "hook"}]
        self.assertFalse(solana_scanner(data, DEFAULT_SETTINGS)[0])
        self.assertTrue(solana_scanner(data, DEFAULT_SETTINGS)[2])

    def test_solana_missing_scanner_core_is_not_safe(self):
        for key in ("freezable", "non_transferable", "transfer_hook", "transfer_fee"):
            data = gp_solana(); data.pop(key)
            self.assertTrue(solana_scanner(data, DEFAULT_SETTINGS)[1], key)

    def test_new_mint_blocks_while_metadata_remains_advisory(self):
        data = gp_solana(); data["mintable"]["status"] = "1"; data["metadata_mutable"]["status"] = "1"
        blocked, unknown, warnings = solana_scanner(data, DEFAULT_SETTINGS)
        self.assertTrue(blocked); self.assertFalse(unknown); self.assertTrue(warnings)

    def test_native_freeze_and_wrong_program_block_or_unknown(self):
        data = native_solana(); data["value"]["data"]["parsed"]["info"]["freezeAuthority"] = "active"
        self.assertTrue(solana_native(data, DEFAULT_SETTINGS)[0])
        self.assertTrue(solana_native(native_solana("custom"), DEFAULT_SETTINGS)[0])

    def test_token2022_restrictions_and_unknown_extensions(self):
        for extension, state in [("nonTransferable", {}), ("permanentDelegate", {"delegate": "active"}),
                                 ("transferHook", {"programId": "hook"}), ("pausableConfig", {"paused": True})]:
            data = native_solana(SPL2022)
            data["value"]["data"]["parsed"]["info"]["extensions"] = [{"extension": extension, "state": state}]
            report = solana_native(data, DEFAULT_SETTINGS)
            if extension in {"nonTransferable", "pausableConfig"}: self.assertTrue(report[0], extension)
            else:
                self.assertFalse(report[0], extension); self.assertTrue(report[2], extension)
        data["value"]["data"]["parsed"]["info"]["extensions"] = [{"extension": "futureExtension"}]
        self.assertTrue(solana_native(data, DEFAULT_SETTINGS)[1])

    def test_token2022_metadata_pointer_is_benign(self):
        data = native_solana(SPL2022)
        data["value"]["data"]["parsed"]["info"]["extensions"] = [{"extension": "metadataPointer", "state": {"authority": "active"}}]
        b, u, _ = solana_native(data, DEFAULT_SETTINGS)
        self.assertFalse(b); self.assertFalse(u)

    def test_sui_blacklist_and_mint_block_while_upgradeability_warns(self):
        data = gp_sui(); data["blacklist"]["value"] = "1"
        self.assertTrue(sui_scanner(data, DEFAULT_SETTINGS)[0])
        data = gp_sui(); data["mintable"]["value"] = "1"; data["contract_upgradeable"]["value"] = "1"
        b, u, w = sui_scanner(data, DEFAULT_SETTINGS)
        self.assertTrue(b); self.assertFalse(u); self.assertTrue(w)
        self.assertTrue(sui_scanner(data, {**DEFAULT_SETTINGS, "security_mode": "strict"})[0])

    def test_sui_case_and_extraction_preserved(self):
        self.assertTrue(canonical_sui(COIN).endswith("::sui::SUI"))
        for full in [COIN, "0x" + "a" * 64 + "::mod::MyCoin"]:
            self.assertEqual(main.extract_first_contract("call " + full, {"evm", "solana", "sui"}), ("sui", full))
        self.assertNotEqual(main.normalize_address(COIN), main.normalize_address(COIN.lower()))


class QuickChecksTest(unittest.IsolatedAsyncioTestCase):
    async def test_fresh_solana_native_fallback_when_scanner_empty(self):
        guard = TokenSecurity()
        with patch.object(guard, "_get", new=AsyncMock(return_value={"code": 1, "result": {}})), \
             patch.object(guard, "_rpc", new=AsyncMock(return_value=native_solana())):
            r = await guard.check("solana", MINT, DEFAULT_SETTINGS)
        self.assertTrue(r.allowed); self.assertTrue(r.warnings)

    async def test_slow_optional_source_does_not_delay_good_native_result(self):
        guard = TokenSecurity()
        async def slow(*args): await asyncio.sleep(10)
        start = time.monotonic()
        with patch.object(guard, "_get", new=AsyncMock(side_effect=slow)), \
             patch.object(guard, "_rpc", new=AsyncMock(return_value=native_solana())):
            r = await guard.check("solana", MINT, DEFAULT_SETTINGS)
        self.assertTrue(r.allowed); self.assertLess(time.monotonic() - start, 0.5)

    async def test_provider_disagreement_hard_block_wins(self):
        guard = TokenSecurity(); bad = native_solana()
        bad = native_solana(SPL2022)
        bad["value"]["data"]["parsed"]["info"]["extensions"] = [{"extension": "nonTransferable", "state": {}}]
        with patch.object(guard, "_get", new=AsyncMock(return_value={"code": 1, "result": {MINT: gp_solana()}})), \
             patch.object(guard, "_rpc", new=AsyncMock(return_value=bad)):
            r = await guard.check("solana", MINT, DEFAULT_SETTINGS)
        self.assertEqual(r.verdict, "blocked")

    async def test_timeout_allows_with_explicit_incomplete_coverage_warning(self):
        guard = TokenSecurity()
        async def slow(*args): await asyncio.sleep(10)
        start = time.monotonic()
        with patch.object(guard, "_get", new=AsyncMock(side_effect=slow)), \
             patch.object(guard, "_rpc", new=AsyncMock(side_effect=slow)):
            r = await guard.check("solana", MINT, {**DEFAULT_SETTINGS, "security_timeout_seconds": 1})
        self.assertTrue(r.allowed); self.assertTrue(r.warnings); self.assertLess(time.monotonic() - start, 1.3)

    async def test_sui_full_type_and_new_mint_is_blocked(self):
        token = gp_sui(); token["mintable"]["value"] = "1"
        guard = TokenSecurity()
        with patch.object(guard, "_get", new=AsyncMock(return_value={"code": 1, "result": {COIN: token}})):
            r = await guard.check("sui", COIN, DEFAULT_SETTINGS)
        self.assertEqual(r.verdict, "blocked"); self.assertEqual(r.checks["forward_address"], canonical_sui(COIN))

    async def test_sui_missing_blacklist_is_an_explicit_warning(self):
        token = gp_sui(); token.pop("blacklist")
        guard = TokenSecurity()
        with patch.object(guard, "_get", new=AsyncMock(return_value={"code": 1, "result": {COIN: token}})):
            r = await guard.check("sui", COIN, DEFAULT_SETTINGS)
        self.assertTrue(r.allowed); self.assertIn("blacklist", r.detail())

    async def test_sui_package_resolution_rejects_ambiguity(self):
        guard = TokenSecurity(); pkg = "0x" + "a" * 64
        mod = {"mod": {"structs": {"ONE": {"abilities": {"abilities": ["Drop"]}}, "TWO": {"abilities": {"abilities": ["Drop"]}}}}}
        with patch.object(guard, "_rpc", new=AsyncMock(side_effect=[mod, {"id": "1"}, {"id": "2"}])):
            async with __import__('aiohttp').ClientSession() as s:
                self.assertIsNone(await resolve_sui(guard, s, pkg))

    async def test_evm_balanced_mintable_blocks_while_missing_tax_is_only_warning(self):
        token = clean_goplus(); token.pop("is_open_source"); token.pop("transfer_tax")
        token["is_mintable"] = "1"; token["slippage_modifiable"] = "1"
        guard = TokenSecurity()
        async def get(session, url, params=None):
            return {"code": 1, "result": {CA: token}} if "goplus" in url else {"pairs": []}
        with patch.object(guard, "_get", side_effect=get):
            r = await guard.check("evm", CA, {**DEFAULT_SETTINGS, "security_chain": "56"})
        self.assertEqual(r.verdict, "blocked")

    async def test_evm_balanced_still_blocks_wallet_traps(self):
        for flag in ("cannot_sell_all", "cannot_buy", "is_honeypot", "is_blacklisted", "is_whitelisted", "transfer_pausable", "is_mintable"):
            token = clean_goplus(); token[flag] = "1"
            guard = TokenSecurity()
            async def get(session, url, params=None):
                return {"code": 1, "result": {CA: token}} if "goplus" in url else {"pairs": []}
            with patch.object(guard, "_get", side_effect=get):
                r = await guard.check("evm", CA, {**DEFAULT_SETTINGS, "security_chain": "56"})
            self.assertEqual(r.verdict, "blocked")


class MultichainBotIntegrationTest(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = baseline.BotIntegrationTest.asyncSetUp
    asyncTearDown = baseline.BotIntegrationTest.asyncTearDown
    event = baseline.BotIntegrationTest.event
    history = baseline.BotIntegrationTest.history
    config = baseline.BotIntegrationTest.config
    async def test_solana_with_warnings_is_forwarded(self):
        with patch.object(TokenSecurity, "check", new=AsyncMock(return_value=SecurityResult("allowed_with_warnings", ["core checked"], warnings=["fresh token"]))):
            await self.event(MINT)
        self.assertEqual(self.client.sent, [(202, MINT)])
        self.assertEqual((await self.history())[0]["security"]["warnings"], ["fresh token"])

    async def test_sui_is_not_sent_to_maestro(self):
        await self.config(destination_bot="@maestro")
        result = SecurityResult("allowed_with_warnings", ["core checked"], checks={"forward_address": canonical_sui(COIN)})
        with patch.object(TokenSecurity, "check", new=AsyncMock(return_value=result)):
            await self.event(COIN)
        self.assertEqual(self.client.attempts, 0)
        self.assertEqual((await self.history())[0]["action"], "unsupported_destination")

    async def test_resolved_sui_type_and_duplicate_for_another_destination(self):
        pkg = "0x" + "a" * 64
        full = pkg + "::mod::MyCoin"
        result = SecurityResult("allowed_with_warnings", ["checked"], checks={"forward_address": full})
        with patch.object(TokenSecurity, "check", new=AsyncMock(return_value=result)):
            await self.event(pkg); await self.event(full)
        self.assertEqual(self.client.sent, [(202, full)])


if __name__ == "__main__": unittest.main()
