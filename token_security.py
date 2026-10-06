"""Read-only screening with evidence-based blocks and explicit coverage warnings. Passing is not a guarantee of future sellability."""
import asyncio
import math
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import aiohttp

CHAINS = {"56": "bsc", "1": "ethereum", "8453": "base"}
KNOWN_BLOCKED = {"0x85ac6c1c7cfd65902fb24bc5485c0d941b93330b"}
# Require explicit answers: absent / empty fields are UNKNOWN, never zero.
RISK_FLAGS = {
    "is_proxy": "Contratto proxy / aggiornabile",
    "is_honeypot": "Honeypot rilevato",
    "is_blacklisted": "Possibilità di bloccare wallet con blacklist",
    "is_whitelisted": "Indirizzi privilegiati / whitelist",
    "transfer_pausable": "Trasferimenti sospendibili",
    "slippage_modifiable": "Tasse modificabili",
    "personal_slippage_modifiable": "Tasse modificabili per singolo wallet",
    "owner_change_balance": "Saldi modificabili dal proprietario",
    "hidden_owner": "Proprietario nascosto",
    "can_take_back_ownership": "Proprietà recuperabile",
    "selfdestruct": "Autodistruzione del contratto",
    "external_call": "Chiamate a contratti esterni",
    "is_mintable": "Possibilità di creare altri token",
    "cannot_sell_all": "Restrizioni alla vendita del saldo completo",
    "cannot_buy": "Acquisti impediti",
    "trading_cooldown": "Restrizioni temporali alle operazioni",
    "anti_whale_modifiable": "Limiti di transazione modificabili",
}
# In balanced mode these capabilities are considered concrete blockers because
# they can directly prevent/privilege transfers or alter supply.
BALANCED_BLOCK_FLAGS = {
    "is_honeypot",
    "cannot_sell_all",
    "cannot_buy",
    "is_blacklisted",
    "is_whitelisted",
    "transfer_pausable",
    "is_mintable",
}
DEFAULT_SETTINGS = {"security_chain": "auto", "security_max_tax_pct": 10.0,
                    "security_min_liquidity_usd": 10000.0,
                    "security_mode": "balanced", "security_timeout_seconds": 2.5}


def number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def validate_settings(raw):
    settings = {key: raw.get(key, value) for key, value in DEFAULT_SETTINGS.items()}
    settings["security_chain"] = str(settings["security_chain"])
    if settings["security_chain"] not in {"auto", *CHAINS}:
        raise ValueError("Rete antifrode non supportata.")
    if settings["security_mode"] not in {"balanced", "strict"}:
        raise ValueError("Modalità antifrode non valida.")
    for key, low, high in [("security_max_tax_pct", 0, 20),
                           ("security_min_liquidity_usd", 0, 1000000),
                           ("security_timeout_seconds", 1, 10)]:
        value = number(settings[key])
        if value is None or not low <= value <= high:
            raise ValueError(f"Valore {key} fuori intervallo: {low}–{high}.")
        settings[key] = value
    return settings


@dataclass
class SecurityResult:
    verdict: str  # allowed, blocked, unknown
    reasons: list[str]
    chain_id: str | None = None
    pair: str | None = None
    checks: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    checked_monotonic: float = field(default_factory=time.monotonic, repr=False)

    @property
    def allowed(self):
        return self.verdict in {"allowed", "allowed_with_warnings"}

    def public(self):
        result = asdict(self)
        result.pop("checked_monotonic")
        return result

    def detail(self):
        return "; ".join(self.reasons + self.warnings)


def evaluate_goplus(token, max_tax):
    blocked, unknown = [], []
    if not isinstance(token, dict) or not token:
        return [], ["GoPlus: dati token assenti"]
    for key, label in RISK_FLAGS.items():
        value = token.get(key)
        if value == "1":
            blocked.append(label)
        elif value != "0":
            unknown.append(f"GoPlus: {key} non verificato")
    for key in ("is_open_source", "is_in_dex"):
        value = token.get(key)
        if value == "0":
            blocked.append("Codice non verificato" if key == "is_open_source" else "Token non negoziato su DEX")
        elif value != "1":
            unknown.append(f"GoPlus: {key} non verificato")
    for key in ("buy_tax", "sell_tax", "transfer_tax"):
        tax = number(token.get(key))
        if tax is None:
            unknown.append(f"GoPlus: {key} non verificata")
        elif tax * 100 > max_tax:
            blocked.append(f"GoPlus: {key} {tax * 100:.2f}% oltre soglia")
    return blocked, unknown


def evaluate_honeypot(data, address, chain_id, pair, max_tax):
    blocked, unknown = [], []
    if not isinstance(data, dict):
        return [], ["Honeypot.is: risposta non valida"]
    token = data.get("token") or {}
    reported_pair = data.get("pair") or {}
    if not isinstance(token, dict) or str(token.get("address", "")).lower() != address:
        unknown.append("Honeypot.is: indirizzo non confermato")
    if not isinstance(reported_pair, dict) or str(reported_pair.get("chainId")) != chain_id:
        unknown.append("Honeypot.is: rete non confermata")
    if not isinstance(reported_pair, dict) or str((reported_pair.get("pair") or {}).get("address", "")).lower() != pair.lower():
        unknown.append("Honeypot.is: pool non confermata")
    result = data.get("honeypotResult") or {}
    if result.get("isHoneypot") is True:
        blocked.append("Honeypot.is: vendita bloccata / honeypot")
    elif result.get("isHoneypot") is not False:
        unknown.append("Honeypot.is: esito honeypot mancante")
    if data.get("simulationSuccess") is not True:
        unknown.append("Honeypot.is: simulazione acquisto/vendita non riuscita")
    sim = data.get("simulationResult") or {}
    for key in ("buyTax", "sellTax", "transferTax"):
        tax = number(sim.get(key))
        if tax is None:
            unknown.append(f"Honeypot.is: {key} non verificata")
        elif tax > max_tax:
            blocked.append(f"Honeypot.is: {key} {tax:.2f}% oltre soglia")
    if sim.get("maxSell") or sim.get("maxBuy"):
        blocked.append("Limiti di acquisto/vendita rilevati; importo Maestro non verificabile")
    code = data.get("contractCode") or {}
    for key, required in [("openSource", True), ("rootOpenSource", True),
                          ("isProxy", False), ("hasProxyCalls", False)]:
        if code.get(key) is not required:
            unknown.append(f"Honeypot.is: codice {key} non conforme/verificato")
    summary = data.get("summary") or {}
    risk = number(summary.get("riskLevel"))
    if risk is None:
        unknown.append("Honeypot.is: livello di rischio assente")
    elif risk > 1:
        blocked.append(f"Honeypot.is: livello di rischio {risk:g}")
    for flag in summary.get("flags", []):
        if isinstance(flag, dict) and flag.get("severity") not in {"info", "low"}:
            blocked.append(f"Honeypot.is: {flag.get('flag', 'segnalazione di rischio')}")
    return blocked, unknown


class TokenSecurity:
    """No signing keys, transaction RPCs, trading, or positive-result cache."""
    async def _get(self, session, url, params=None):
        async with session.get(url, params=params, allow_redirects=False) as response:
            if response.status != 200:
                raise ValueError(f"API HTTP {response.status}")
            # Bound memory usage; do not log untrusted HTTP bodies or credentials.
            body = bytearray()
            async for chunk in response.content.iter_chunked(65536):
                body.extend(chunk)
                if len(body) > 2_000_000:
                    raise ValueError("Risposta API troppo grande")
            import json
            return json.loads(body)

    async def check(self, kind, address, settings):
        started = time.monotonic()
        if kind not in {"evm", "solana", "sui"}:
            return SecurityResult("unknown", ["Rete non supportata"])
        if kind == "evm" and not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            return SecurityResult("unknown", ["Indirizzo EVM non valido"])
        from non_evm_security import valid_mint, canonical_sui
        if kind == "solana" and not valid_mint(address):
            return SecurityResult("unknown", ["Mint Solana non valido"])
        if kind == "sui" and not (canonical_sui(address) or re.fullmatch(r"0x[0-9a-fA-F]{64}", address)):
            return SecurityResult("unknown", ["Tipo coin Sui non valido"])
        address = address.lower() if kind == "evm" else address
        if address in KNOWN_BLOCKED:
            return SecurityResult("blocked", ["MCPAD: contratto con blocchi malevoli già verificati"])
        try:
            settings = validate_settings(settings)
            async with asyncio.timeout(settings["security_timeout_seconds"]):
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=settings["security_timeout_seconds"]), trust_env=True) as session:
                    if kind != "evm":
                        from non_evm_security import check_non_evm
                        result = await check_non_evm(self, session, kind, address, settings)
                    elif settings["security_mode"] == "balanced":
                        result = await self._check_evm_balanced(session, address, settings)
                    else:
                        result = await self._check_evm(session, address, settings)
                    result.checks["elapsed_ms"] = round((time.monotonic() - started) * 1000)
                    result.checks["address"] = address
                    result.checks["mode"] = settings["security_mode"]
                    if result.verdict == "unknown" and settings["security_mode"] == "balanced" and not result.checks.get("identity_error"):
                        result.verdict = "allowed_with_warnings"
                        result.warnings = list(dict.fromkeys(result.reasons + result.warnings))
                        result.reasons = ["Nessun blocco concreto rilevato nei dati disponibili; verifica incompleta"]
                    return result
        except (TimeoutError, aiohttp.ClientError, ValueError, TypeError, KeyError, AttributeError):
            checks = {"elapsed_ms": round((time.monotonic() - started) * 1000), "address": address,
                      "mode": settings.get("security_mode"), "coverage": "incomplete"}
            if settings.get("security_mode") == "balanced" and (kind != "sui" or canonical_sui(address)):
                if kind == "sui": checks["forward_address"] = canonical_sui(address)
                return SecurityResult("allowed_with_warnings", ["Inoltro con verifica incompleta"],
                                      chain_id=kind if kind != "evm" else None, checks=checks,
                                      warnings=["Timeout/API indisponibile: nessuna verifica completa di vendibilità; rischio non escluso"])
            return SecurityResult("unknown", ["Verifica incompleta / identificazione non riuscita"], checks=checks)

    async def _rpc(self, session, url, method, params):
        async with session.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}) as response:
            if response.status != 200:
                raise ValueError(f"RPC HTTP {response.status}")
            data = await response.json()
            if not isinstance(data, dict) or "error" in data or "result" not in data:
                raise ValueError("RPC: risposta non valida")
            return data["result"]

    async def _check_evm_balanced(self, session, address, settings):
        from non_evm_security import finish
        candidates = list(CHAINS) if settings["security_chain"] == "auto" else [settings["security_chain"]]
        market = asyncio.create_task(self._get(session, f"https://api.dexscreener.com/latest/dex/tokens/{address}"))
        tasks = {asyncio.create_task(self._get(session, f"https://api.gopluslabs.io/api/v1/token_security/{c}",
                                             {"contract_addresses": address})): c for c in candidates}
        pending = set(tasks); found = {}; blocked = []; warnings = []; errors = []
        deadline = asyncio.get_running_loop().time() + max(0.05, settings["security_timeout_seconds"] - 0.1)
        grace_deadline = deadline
        try:
            while pending:
                done, pending = await asyncio.wait(pending, timeout=max(0, min(deadline, grace_deadline) - asyncio.get_running_loop().time()),
                                                   return_when=asyncio.FIRST_COMPLETED)
                if not done: break
                for task in done:
                    chain = tasks[task]
                    try:
                        data = task.result()
                        token = (data.get("result") or {}).get(address) if data.get("code") == 1 else None
                        if not token: continue
                        found[chain] = token
                        for key, label in RISK_FLAGS.items():
                            value = token.get(key)
                            if value == "1":
                                (blocked if key in BALANCED_BLOCK_FLAGS else warnings).append(label)
                            elif value != "0": warnings.append(f"GoPlus: {key} non verificato")
                        for key in ("buy_tax", "sell_tax", "transfer_tax"):
                            tax = number(token.get(key))
                            if tax is None: warnings.append(f"{key}: dato non disponibile")
                            elif tax * 100 > settings["security_max_tax_pct"]:
                                blocked.append(f"{key} {tax * 100:.2f}% oltre soglia")
                        if token.get("is_open_source") != "1": warnings.append("Codice non verificato: analisi incompleta")
                    except Exception:
                        errors.append(f"Scanner {CHAINS[chain]} indisponibile")
                if len(found) > 1:
                    return SecurityResult("unknown", ["Stesso indirizzo presente su più reti: identificazione ambigua"],
                                          checks={"identity_error": True, "networks": list(found)})
                # Known concrete danger must not be lost while another network times out.
                if blocked: break
                if found: grace_deadline = min(grace_deadline, asyncio.get_running_loop().time() + 0.03)
            if pending: warnings.append("Riconoscimento EVM parziale: alcune reti non hanno risposto nel budget")
            warnings.extend(errors)
            chain = next(iter(found), None)
            token = found.get(chain, {})
            pairs = []
            if market.done() and not market.cancelled():
                try: pairs = market.result().get("pairs") or []
                except Exception: pass
            pairs = [p for p in pairs if isinstance(p, dict) and p.get("chainId") in CHAINS.values() and
                     str((p.get("baseToken") or {}).get("address", "")).lower() == address]
            networks = {p.get("chainId") for p in pairs} | ({CHAINS[chain]} if chain else set())
            if settings["security_chain"] == "auto" and len(networks) > 1:
                return SecurityResult("unknown", ["Indirizzo presente su più reti: impossibile scegliere automaticamente"], checks={"identity_error": True})
            if chain is None and len(networks) == 1:
                chain = next(c for c in CHAINS if CHAINS[c] in networks)
            if not token: warnings.append("Scanner non indicizzato: honeypot, privilegi e tasse non verificati")
            if chain is None: warnings.append("Rete EVM specifica non confermata; indirizzo riconosciuto come EVM")
            pairs = [p for p in pairs if chain and p.get("chainId") == CHAINS[chain]]
            liquidity = max((number((p.get("liquidity") or {}).get("usd")) or 0 for p in pairs), default=None)
            if liquidity is None: warnings.append("Pool/liquidità non indicizzate: possibile lancio recente")
            elif liquidity < settings["security_min_liquidity_usd"]:
                warnings.append(f"Liquidità ${liquidity:,.0f} sotto soglia di avviso")
            warnings.append("Nessuna simulazione acquisto/vendita; wallet e importo destinazione non verificati")
            identity = (pairs[0].get("baseToken") or {}) if pairs else {}
            return finish(blocked, [], list(dict.fromkeys(warnings)), chain,
                          {"name": token.get("token_name") or identity.get("name"),
                           "symbol": token.get("token_symbol") or identity.get("symbol"),
                           "goplus": {k: token.get(k) for k in (*RISK_FLAGS, "is_open_source", "buy_tax", "sell_tax", "transfer_tax")},
                           "liquidity_usd": liquidity, "networks_checked": [tasks[t] for t in tasks if t.done() and not t.cancelled()],
                           "coverage": "partial" if pending or errors or not token else "scanner"})
        finally:
            for task in [market, *tasks]: task.cancel()
            await asyncio.gather(market, *tasks, return_exceptions=True)

    async def _check_evm(self, session, address, settings):
        chain_id = settings["security_chain"]
        if chain_id == "auto":
            payload = await self._get(session, f"https://api.dexscreener.com/latest/dex/tokens/{address}")
            pairs = payload.get("pairs") or []
        else:
            pairs = await self._get(session, f"https://api.dexscreener.com/token-pairs/v1/{CHAINS[chain_id]}/{address}")
        if not isinstance(pairs, list):
            return SecurityResult("unknown", ["DEX: dati pool non validi"])
        pairs = [p for p in pairs if isinstance(p, dict) and
                 str((p.get("baseToken") or {}).get("address", "")).lower() == address]
        networks = {p.get("chainId") for p in pairs}
        if chain_id == "auto":
            if len(networks) != 1:
                return SecurityResult("unknown", ["Rete assente o ambigua: seleziona la rete nel pannello"])
            network = next(iter(networks))
            chain_id = next((c for c, slug in CHAINS.items() if slug == network), None)
            if chain_id is None:
                return SecurityResult("unknown", ["Rete EVM non supportata: inoltro bloccato"])
        pairs = [p for p in pairs if p.get("chainId") == CHAINS[chain_id] and
                 re.fullmatch(r"0x[0-9a-fA-F]{40}", str(p.get("pairAddress", "")))]
        if not pairs:
            return SecurityResult("unknown", ["Nessuna pool verificabile sulla rete selezionata"], chain_id)
        pair = max(pairs, key=lambda p: number((p.get("liquidity") or {}).get("usd")) or 0)
        pair_address = pair["pairAddress"]
        liquidity = number((pair.get("liquidity") or {}).get("usd"))
        if liquidity is None:
            return SecurityResult("unknown", ["Liquidità non verificabile"], chain_id, pair_address)
        if liquidity < settings["security_min_liquidity_usd"]:
            return SecurityResult("blocked", [f"Liquidità pool ${liquidity:,.0f} sotto soglia"], chain_id, pair_address)
        results = await asyncio.gather(
            self._get(session, f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}",
                      {"contract_addresses": address}),
            self._get(session, "https://api.honeypot.is/v2/IsHoneypot",
                      {"address": address, "chainID": chain_id, "pair": pair_address}),
            return_exceptions=True,
        )
        blocked, unknown, checks = [], [], {"liquidity_usd": liquidity}
        gp, hp = results
        if isinstance(gp, Exception) or not isinstance(gp, dict) or gp.get("code") != 1:
            unknown.append("GoPlus: API indisponibile / risposta non valida")
        else:
            token = (gp.get("result") or {}).get(address)
            b, u = evaluate_goplus(token, settings["security_max_tax_pct"])
            blocked.extend(b); unknown.extend(u)
            checks["goplus"] = {k: token.get(k) for k in (*RISK_FLAGS, "is_open_source", "buy_tax", "sell_tax", "transfer_tax")} if isinstance(token, dict) else {}
        if isinstance(hp, Exception):
            unknown.append("Honeypot.is: API indisponibile")
        else:
            b, u = evaluate_honeypot(hp, address, chain_id, pair_address, settings["security_max_tax_pct"])
            blocked.extend(b); unknown.extend(u)
            checks["honeypot"] = {"simulation_success": hp.get("simulationSuccess"),
                                  "simulation": hp.get("simulationResult"), "summary": hp.get("summary")} if isinstance(hp, dict) else {}
        verdict = "blocked" if blocked else "unknown" if unknown else "allowed"
        reasons = blocked + unknown or ["Controlli disponibili superati; nessuna garanzia contro frodi future"]
        return SecurityResult(verdict, reasons, chain_id, pair_address, checks)
