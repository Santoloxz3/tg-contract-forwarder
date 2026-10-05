import asyncio
import copy
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import aiohttp
import main
from token_security import (DEFAULT_SETTINGS, KNOWN_BLOCKED, RISK_FLAGS,
                            SecurityResult, TokenSecurity, evaluate_goplus,
                            evaluate_honeypot, validate_settings)

CA = "0x" + "1" * 40
PAIR = "0x" + "2" * 40


def clean_goplus():
    return {**dict.fromkeys(RISK_FLAGS, "0"), "is_open_source": "1", "is_in_dex": "1",
            "buy_tax": "0.02", "sell_tax": "0.02", "transfer_tax": "0"}


def clean_honeypot():
    return {"token": {"address": CA}, "pair": {"chainId": "56", "pair": {"address": PAIR}},
            "simulationSuccess": True, "honeypotResult": {"isHoneypot": False},
            "simulationResult": {"buyTax": 2, "sellTax": 2, "transferTax": 0},
            "contractCode": {"openSource": True, "rootOpenSource": True,
                             "isProxy": False, "hasProxyCalls": False},
            "summary": {"riskLevel": 0, "flags": []}}


class RulesTest(unittest.TestCase):
    def test_each_dangerous_privilege_blocks_even_when_honeypot_is_zero(self):
        for flag in RISK_FLAGS:
            with self.subTest(flag=flag):
                token = clean_goplus(); token[flag] = "1"
                self.assertTrue(evaluate_goplus(token, 10)[0])

    def test_missing_empty_or_malformed_flags_are_unknown(self):
        for value in [None, "", "false", False, 0]:
            token = clean_goplus(); token["is_blacklisted"] = value
            self.assertTrue(evaluate_goplus(token, 10)[1])

    def test_mcpad_scanner_false_negative_is_still_blocked(self):
        token = clean_goplus()
        token.update(is_honeypot="0", is_blacklisted="1", is_whitelisted="1",
                     transfer_pausable="1", slippage_modifiable="1")
        blocked, _ = evaluate_goplus(token, 10)
        self.assertEqual(len(blocked), 4)

    def test_taxes_use_correct_units_and_reject_nan(self):
        gp = clean_goplus(); gp["sell_tax"] = "0.11"
        hp = clean_honeypot(); hp["simulationResult"]["sellTax"] = 11
        self.assertTrue(evaluate_goplus(gp, 10)[0])
        self.assertTrue(evaluate_honeypot(hp, CA, "56", PAIR, 10)[0])
        for value in ["NaN", "Infinity", -1, "", None, True]:
            gp["sell_tax"] = value
            self.assertTrue(evaluate_goplus(gp, 10)[1])

    def test_identity_and_simulation_required(self):
        for mutation in [lambda d: d.update(simulationSuccess=False),
                         lambda d: d["pair"].update(chainId="1"),
                         lambda d: d["token"].update(address=PAIR),
                         lambda d: d["pair"]["pair"].update(address=CA),
                         lambda d: d.pop("contractCode"),
                         lambda d: d["honeypotResult"].pop("isHoneypot")]:
            d = clean_honeypot(); mutation(d)
            self.assertTrue(evaluate_honeypot(d, CA, "56", PAIR, 10)[1])

    def test_settings_cannot_disable_filter_or_use_invalid_numbers(self):
        for raw in [{"security_max_tax_pct": "nan"}, {"security_min_liquidity_usd": 0},
                    {"security_max_tax_pct": 100}, {"security_chain": "137"}]:
            with self.assertRaises(ValueError):
                validate_settings(raw)

    def test_existing_db_migration_preserves_history_and_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "history.db")
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE ca_events(id INTEGER PRIMARY KEY, event_at TEXT DEFAULT CURRENT_TIMESTAMP, chain_type TEXT, address TEXT, action TEXT, detail TEXT, source_chat TEXT, destination_bot TEXT)")
            db.execute("INSERT INTO ca_events(action, address) VALUES('forwarded', ?)", (CA,))
            db.commit(); db.close()
            with patch.dict(os.environ, {"SOURCE_CHAT": "@old", "DESTINATION_BOT": "@maestro"}):
                db = main.open_db(path)
                self.assertEqual(main.recent_events(db)[0]["address"], CA)
                cfg = main.load_saved_config(db)
                self.assertEqual(cfg["security_chain"], "auto")
                cfg.update(security_chain="56", security_max_tax_pct=5)
                main.save_config(db, cfg)
                self.assertEqual(main.load_saved_config(db)["security_max_tax_pct"], 5)
                db.close()


class ProvidersTest(unittest.IsolatedAsyncioTestCase):
    async def test_chunked_http_response_is_read_completely(self):
        import json
        from aiohttp import web
        from aiohttp.test_utils import TestServer
        async def response(request):
            out = web.StreamResponse(headers={"Content-Type": "application/json"})
            await out.prepare(request)
            payload = json.dumps({"data": "x" * 150000}).encode()
            for start in range(0, len(payload), 2048):
                await out.write(payload[start:start+2048])
                await asyncio.sleep(0)
            await out.write_eof()
            return out
        app = web.Application(); app.router.add_get("/", response)
        async with TestServer(app) as server:
            async with aiohttp.ClientSession() as session:
                result = await TokenSecurity()._get(session, str(server.make_url("/")))
                self.assertEqual(len(result["data"]), 150000)

    def pair(self, network="bsc", liquidity=20000):
        return {"chainId": network, "pairAddress": PAIR, "baseToken": {"address": CA},
                "liquidity": {"usd": liquidity}}

    async def run_check(self, pairs=None, gp=None, hp=None):
        guard = TokenSecurity()
        async def get(session, url, params=None):
            if "dexscreener" in url:
                return {"pairs": pairs if pairs is not None else [self.pair()]}
            if "goplus" in url:
                value = gp if gp is not None else {"code": 1, "result": {CA: clean_goplus()}}
            else:
                value = hp if hp is not None else clean_honeypot()
            if isinstance(value, Exception):
                raise value
            return value
        with patch.object(guard, "_get", side_effect=get):
            return await guard.check("evm", CA, DEFAULT_SETTINGS)

    async def test_complete_reports_allow(self):
        self.assertTrue((await self.run_check()).allowed)

    async def test_unknown_and_unsupported_never_allow(self):
        for kind, address in [("solana", "a" * 40), ("sui", "0x" + "1" * 64), ("evm", "invalid")]:
            self.assertFalse((await TokenSecurity().check(kind, address, DEFAULT_SETTINGS)).allowed)
        self.assertFalse((await self.run_check(pairs=[])).allowed)
        self.assertFalse((await self.run_check(pairs=[self.pair("polygon")])).allowed)
        self.assertFalse((await self.run_check(pairs=[self.pair(), self.pair("ethereum")])).allowed)
        self.assertFalse((await self.run_check(pairs=[self.pair(liquidity=9999)])).allowed)
        self.assertFalse((await self.run_check(gp=TimeoutError())).allowed)
        self.assertFalse((await self.run_check(hp=ValueError("HTTP 403"))).allowed)
        self.assertFalse((await self.run_check(gp={"code": 1, "result": {}})).allowed)

    async def test_mcpad_blocked_without_network(self):
        guard = TokenSecurity()
        with patch.object(guard, "_get", side_effect=AssertionError("Network must not be needed")):
            report = await guard.check("evm", next(iter(KNOWN_BLOCKED)), DEFAULT_SETTINGS)
        self.assertEqual(report.verdict, "blocked")

    async def test_block_wins_over_other_provider_failure(self):
        token = clean_goplus(); token["is_blacklisted"] = "1"
        report = await self.run_check(gp={"code": 1, "result": {CA: token}}, hp=TimeoutError())
        self.assertEqual(report.verdict, "blocked")


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.sent, self.attempts = [], 0
        self.stop = asyncio.Event()
        self.flood = False

    async def start(self): pass
    async def get_me(self): return SimpleNamespace(id=42, username="test")
    async def get_entity(self, peer): return peer
    def on(self, event):
        def register(callback): self.handler = callback; return callback
        return register
    async def run_until_disconnected(self): await self.stop.wait()
    async def send_message(self, destination, address):
        self.attempts += 1
        if self.flood:
            self.flood = False
            raise main.FloodWaitError(request=None, capture=0)
        self.sent.append((destination, address))
        return SimpleNamespace(id=99)


class BotIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.client = FakeClient()
        self.site = None
        original_site = main.web.TCPSite
        def site_factory(runner, host, port):
            self.site = original_site(runner, "127.0.0.1", 0)
            return self.site
        self.patches = [patch.dict(os.environ, {"TELEGRAM_API_ID": "1", "TELEGRAM_API_HASH": "test",
            "TELEGRAM_SESSION_STRING": "test", "SOURCE_CHAT": "101", "DESTINATION_BOT": "202",
            "SOURCE_SENDER": "", "REQUIRE_KEYWORD": "", "DRY_RUN": "false", "FORWARD_DELAY_SECONDS": "0",
            "HISTORY_DB_PATH": str(Path(self.folder.name) / "db.sqlite3"),
            "PANEL_PASSWORD": "test", "PANEL_SECRET": "test-cookie"}),
            patch.object(main, "TelegramClient", return_value=self.client),
            patch.object(main, "StringSession", return_value=None),
            patch.object(main, "get_peer_id", side_effect=lambda value: value),
            patch.object(main.web, "TCPSite", side_effect=site_factory)]
        for p in self.patches: p.start()
        self.task = asyncio.create_task(main.main())
        for _ in range(100):
            if self.task.done(): await self.task
            if self.site and self.site._server: break
            await asyncio.sleep(0.01)
        self.url = "http://127.0.0.1:" + str(self.site._server.sockets[0].getsockname()[1])
        self.http = aiohttp.ClientSession(headers={"Cookie": "ca_panel=test-cookie"})

    async def asyncTearDown(self):
        self.client.stop.set(); await self.task
        await self.http.close()
        for p in reversed(self.patches): p.stop()
        self.folder.cleanup()

    async def event(self, address=CA):
        await self.client.handler(SimpleNamespace(chat_id=101, raw_text=address))

    async def history(self):
        async with self.http.get(self.url + "/api/history") as r: return (await r.json())["events"]

    async def config(self, **updates):
        async with self.http.get(self.url + "/api/config") as r: cfg = await r.json()
        cfg.update(updates)
        async with self.http.post(self.url + "/api/config", json=cfg) as r:
            self.assertEqual(r.status, 200)

    async def test_blocked_and_unknown_make_zero_send_attempts(self):
        for verdict in ["blocked", "unknown"]:
            with patch.object(TokenSecurity, "check", new=AsyncMock(return_value=SecurityResult(verdict, ["test"]))):
                await self.event()
                self.assertEqual(self.client.attempts, 0)
                events = await self.history()
                self.assertEqual(events[0]["action"], "security_" + verdict)
                self.assertEqual(events[0]["security"]["verdict"], verdict)

    async def test_allowed_forward_and_duplicate(self):
        with patch.object(TokenSecurity, "check", new=AsyncMock(return_value=SecurityResult("allowed", ["test"]))):
            await self.event(); await self.event()
        self.assertEqual(self.client.sent, [(202, CA)])
        self.assertEqual((await self.history())[0]["action"], "duplicate_ignored")

    async def test_dry_run_checks_but_does_not_send(self):
        await self.config(dry_run=True)
        checker = AsyncMock(return_value=SecurityResult("allowed", ["test"]))
        with patch.object(TokenSecurity, "check", new=checker): await self.event()
        self.assertEqual(checker.await_count, 1)
        self.assertEqual(self.client.attempts, 0)
        self.assertEqual((await self.history())[0]["action"], "dry_run")

    async def test_real_known_scam_and_unsupported_chain_do_not_send(self):
        await self.event(next(iter(KNOWN_BLOCKED)))
        await self.event("0x" + "1" * 64)
        self.assertEqual(self.client.attempts, 0)

    async def test_floodwait_requires_new_security_check(self):
        self.client.flood = True
        checker = AsyncMock(side_effect=[SecurityResult("allowed", ["test"]), SecurityResult("blocked", ["blacklist appeared"])])
        with patch.object(TokenSecurity, "check", new=checker): await self.event()
        self.assertEqual(checker.await_count, 2)
        self.assertEqual(self.client.attempts, 1)
        self.assertEqual(self.client.sent, [])

    async def test_config_change_during_check_prevents_old_destination_send(self):
        async def changed(*args):
            await self.config(destination_bot="303")
            return SecurityResult("allowed", ["test"])
        with patch.object(TokenSecurity, "check", new=AsyncMock(side_effect=changed)): await self.event()
        self.assertEqual(self.client.attempts, 0)
        self.assertEqual((await self.history())[0]["action"], "stale_ignored")

    async def test_manual_check_never_forwards_and_auth_required(self):
        async with self.http.post(self.url + "/api/security/check", json={"address": next(iter(KNOWN_BLOCKED))}) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual((await r.json())["verdict"], "blocked")
        self.assertEqual(self.client.attempts, 0)
        async with aiohttp.ClientSession() as anonymous:
            async with anonymous.post(self.url + "/api/security/check", json={"address": CA}) as r:
                self.assertEqual(r.status, 401)


if __name__ == "__main__": unittest.main()
