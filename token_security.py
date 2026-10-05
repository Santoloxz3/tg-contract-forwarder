"""Read-only, fail-closed screening. Passing is not a guarantee of future sellability."""
import asyncio
import math
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
DEFAULT_SETTINGS = {"security_chain": "auto", "security_max_tax_pct": 10.0,
                    "security_min_liquidity_usd": 10000.0}


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
    for key, low, high in [("security_max_tax_pct", 0, 20),
                           ("security_min_liquidity_usd", 1000, 1000000)]:
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
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    checked_monotonic: float = field(default_factory=time.monotonic, repr=False)

    @property
    def allowed(self):
        return self.verdict == "allowed"

    def public(self):
        result = asdict(self)
        result.pop("checked_monotonic")
        return result

    def detail(self):
        return "; ".join(self.reasons)


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
        if kind != "evm":
            return SecurityResult("unknown", [f"Controllo {kind} non ancora disponibile: inoltro bloccato"])
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            return SecurityResult("unknown", ["Indirizzo EVM non valido"])
        address = address.lower()
        if address in KNOWN_BLOCKED:
            return SecurityResult("blocked", ["MCPAD: contratto con blocchi malevoli già verificati"])
        try:
            settings = validate_settings(settings)
            async with asyncio.timeout(22):
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    return await self._check_evm(session, address, settings)
        except (TimeoutError, aiohttp.ClientError, ValueError, TypeError, KeyError, AttributeError):
            return SecurityResult("unknown", ["Verifica incompleta / API indisponibile: inoltro bloccato"])

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
