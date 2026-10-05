"""Native-chain screening: absent market data is an advisory, absent core checks is not."""
import asyncio
import os
import re

from token_security import SecurityResult, number

SPL = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SPL2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SUI_TYPE = re.compile(r"0x[0-9a-fA-F]{1,64}::[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*")


def finish(blocked, unknown, warnings, chain, checks):
    verdict = "blocked" if blocked else "unknown" if unknown else "allowed_with_warnings" if warnings else "allowed"
    return SecurityResult(verdict, blocked + unknown or ["Controlli essenziali disponibili superati"],
                          chain_id=chain, checks=checks, warnings=warnings)


def valid_mint(address):
    if not isinstance(address, str) or not 32 <= len(address) <= 44:
        return False
    value = 0
    for c in address:
        if c not in BASE58:
            return False
        value = value * 58 + BASE58.index(c)
    leading = len(address) - len(address.lstrip("1"))
    return leading + (value.bit_length() + 7) // 8 == 32


def canonical_sui(address):
    if not SUI_TYPE.fullmatch(address):
        return None
    package, module, token = address.split("::")
    return f"0x{int(package, 16):064x}::{module}::{token}"


def status(item, field="status"):
    value = item.get(field) if isinstance(item, dict) else None
    return str(value) if value in ("0", "1", "2", 0, 1, 2) and not isinstance(value, bool) else None


def scalar(value):
    return status({"status": value})


def solana_scanner(token, settings):
    blocked, unknown, warnings = [], [], []
    if not isinstance(token, dict) or not token:
        return [], ["Scanner Solana: mint non ancora indicizzato"], []
    for key in ("freezable", "balance_mutable_authority", "closable", "default_account_state_upgradable", "transfer_fee_upgradable", "transfer_hook_upgradable"):
        s = status(token.get(key))
        if s == "1": blocked.append(f"Solana: {key} attivo")
        elif s != "0": unknown.append(f"Solana: {key} non verificato")
    if scalar(token.get("non_transferable")) == "1": blocked.append("Solana: token non trasferibile")
    elif scalar(token.get("non_transferable")) != "0": unknown.append("Solana: trasferibilità non verificata")
    if scalar(token.get("default_account_state")) in {"0", "2"}: blocked.append("Solana: nuovi account non inizializzati/congelati")
    elif scalar(token.get("default_account_state")) != "1": unknown.append("Solana: stato account non verificato")
    hooks = token.get("transfer_hook")
    if hooks: blocked.append("Solana: transfer hook può imporre restrizioni alle vendite")
    elif not isinstance(hooks, list): unknown.append("Solana: transfer hook non verificato")
    if not isinstance(token.get("transfer_fee"), dict):
        unknown.append("Solana: transfer fee non verificata")
    for fee in (token.get("transfer_fee") or {}).values():
        if isinstance(fee, dict):
            rate = number(fee.get("fee_rate"))
            if rate is None: unknown.append("Solana: transfer fee non verificata")
            elif rate / 100 > settings["security_max_tax_pct"]: blocked.append("Solana: tassa di trasferimento oltre soglia")
    for key in ("mintable", "metadata_mutable"):
        if status(token.get(key)) == "1": warnings.append(f"Solana: {key} attivo")
    if settings["security_mode"] == "strict":
        mint = status(token.get("mintable"))
        if mint == "1": blocked.append("Solana: mint attivo non ammesso in modalità prudente")
        elif mint != "0": unknown.append("Solana: mint non verificato in modalità prudente")
    for creator in token.get("creators", []):
        if isinstance(creator, dict) and str(creator.get("malicious_address")) == "1":
            blocked.append("Solana: creatore segnalato malevolo")
    if not token.get("dex"): warnings.append("DEX non ancora indicizzato; nessuna soglia minima obbligatoria in modalità bilanciata")
    return blocked, unknown, warnings


def solana_native(result, settings):
    blocked, unknown, warnings = [], [], []
    account = result.get("value") if isinstance(result, dict) else None
    if not isinstance(account, dict) or account.get("owner") not in {SPL, SPL2022} or account.get("executable") is not False:
        return [], ["RPC Solana: non è un mint SPL verificabile"], []
    parsed = (account.get("data") or {}).get("parsed") or {}
    info = parsed.get("info") or {}
    if parsed.get("type") != "mint" or info.get("isInitialized") is not True:
        return [], ["RPC Solana: mint non inizializzato/verificato"], []
    if "freezeAuthority" not in info:
        unknown.append("RPC Solana: freeze authority non verificata")
    elif info["freezeAuthority"] is not None:
        blocked.append("Solana: autorità di congelamento attiva")
    if info.get("mintAuthority"):
        warnings.append("Solana: autorità di mint attiva (rischio diluizione)")
        if settings["security_mode"] == "strict": blocked.append("Solana: mint attivo non ammesso in modalità prudente")
    elif "mintAuthority" not in info and settings["security_mode"] == "strict":
        unknown.append("Solana: mint authority non verificata")
    if account["owner"] == SPL2022:
        extensions = info.get("extensions")
        if not isinstance(extensions, list):
            unknown.append("Solana Token-2022: estensioni non verificabili")
        else:
            neutral = {"metadataPointer", "tokenMetadata", "groupPointer", "tokenGroup",
                       "groupMemberPointer", "tokenGroupMember", "interestBearingConfig", "scaledUiAmountConfig"}
            for item in extensions:
                kind = item.get("extension")
                state = item.get("state") or {}
                if kind in neutral:
                    continue
                if kind == "transferFeeConfig":
                    if state.get("transferFeeConfigAuthority") is not None:
                        blocked.append("Solana: commissioni modificabili")
                    elif "transferFeeConfigAuthority" not in state:
                        unknown.append("Solana: autorità commissioni non verificata")
                    for key in ("olderTransferFee", "newerTransferFee"):
                        rate = number((state.get(key) or {}).get("transferFeeBasisPoints"))
                        if rate is None: unknown.append("Solana: commissione non verificata")
                        elif rate / 100 > settings["security_max_tax_pct"]: blocked.append("Solana: commissione oltre soglia")
                elif kind == "defaultAccountState":
                    if state.get("accountState") != "initialized":
                        blocked.append("Solana: stato account restrittivo")
                elif kind == "transferHook":
                    if state.get("programId") or state.get("authority"):
                        blocked.append("Solana: hook sui trasferimenti attivo/modificabile")
                    elif not {"programId", "authority"} <= state.keys():
                        unknown.append("Solana: hook non verificato")
                elif kind == "permanentDelegate":
                    if state.get("delegate"):
                        blocked.append("Solana: delegato permanente può trasferire/bruciare i saldi")
                    elif "delegate" not in state: unknown.append("Solana: delegato non verificato")
                elif kind == "mintCloseAuthority":
                    if state.get("closeAuthority"): blocked.append("Solana: mint chiudibile")
                    elif "closeAuthority" not in state: unknown.append("Solana: close authority non verificata")
                elif kind in {"nonTransferable", "pausableConfig", "permissionedBurn"}:
                    blocked.append(f"Solana: estensione restrittiva {kind}")
                else:
                    unknown.append(f"Solana: estensione {kind} non ancora analizzata")
    return blocked, unknown, warnings


async def check_solana(guard, session, address, settings):
    if not valid_mint(address): return SecurityResult("unknown", ["Mint Solana non valido"], "solana")
    gp = asyncio.create_task(guard._get(session, "https://api.gopluslabs.io/api/v1/solana/token_security", {"contract_addresses": address}))
    rpc = asyncio.create_task(guard._rpc(session, os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
                                       "getAccountInfo", [address, {"encoding": "jsonParsed", "commitment": "processed"}]))
    pending = {gp, rpc}; reports = {}; warnings = []; blocked = []
    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    data = task.result()
                    if task is gp:
                        token = (data.get("result") or {}).get(address) if data.get("code") == 1 else None
                        report = solana_scanner(token, settings)
                    else:
                        report = solana_native(data, settings)
                    reports["goplus" if task is gp else "rpc"] = report
                    blocked.extend(report[0]); warnings.extend(report[2])
                except Exception:
                    reports["goplus" if task is gp else "rpc"] = ([], ["Servizio indisponibile"], [])
            if blocked:
                return finish(blocked, [], warnings, "solana", {"providers": reports})
            if any(not b and not u for b, u, w in reports.values()):
                # Briefly consume an already-running second source, never wait for indexing.
                if pending:
                    extra, pending = await asyncio.wait(pending, timeout=0.1)
                    for task in extra:
                        try:
                            data = task.result()
                            if task is gp:
                                token = (data.get("result") or {}).get(address) if data.get("code") == 1 else None
                                b, u, w = solana_scanner(token, settings)
                            else: b, u, w = solana_native(data, settings)
                            blocked.extend(b); warnings.extend(w)
                        except Exception: pass
                if settings["security_mode"] == "strict":
                    warnings.append("Copertura Solana nativa/scanner; simulazione di vendita non disponibile")
                if len(reports) < 2 or any(u for b, u, w in reports.values()):
                    warnings.append("Copertura rapida/parziale: controlli essenziali verificati da una fonte")
                warnings.append("Controllo mint/autorità: nessuna simulazione di vendita o verifica dell'importo Maestro")
                return finish(blocked, [], list(dict.fromkeys(warnings)), "solana", {"providers": reports})
        return finish([], ["Nessuna fonte verifica tutti i controlli essenziali Solana"], warnings, "solana", {"providers": reports})
    finally:
        for task in (gp, rpc): task.cancel()
        await asyncio.gather(gp, rpc, return_exceptions=True)


async def resolve_sui(guard, session, address):
    full = canonical_sui(address)
    if full: return full
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", address): return None
    url = os.getenv("SUI_RPC_URL", "https://fullnode.mainnet.sui.io:443")
    modules = await guard._rpc(session, url, "sui_getNormalizedMoveModulesByPackage", [address])
    candidates = []
    for module_name, module in modules.items():
        for name, struct in (module.get("structs") or {}).items():
            abilities = (struct.get("abilities") or {}).get("abilities", [])
            if not struct.get("fields") and not struct.get("typeParameters") and "Drop" in abilities:
                candidates.append(f"{address.lower()}::{module_name}::{name}")
    if not 1 <= len(candidates) <= 4: return None
    result = await asyncio.gather(*(guard._rpc(session, url, "suix_getCoinMetadata", [c]) for c in candidates), return_exceptions=True)
    coins = [c for c, metadata in zip(candidates, result) if isinstance(metadata, dict) and metadata.get("id")]
    return coins[0] if len(coins) == 1 else None


def sui_scanner(token, settings):
    blocked, unknown, warnings = [], [], []
    if not isinstance(token, dict) or not token:
        return [], ["Sui: coin non ancora indicizzata; blacklist non verificabile"], []
    black = status(token.get("blacklist"), "value")
    if black in {"1", "2"}: blocked.append("Sui: DenyCap/blacklist può bloccare wallet")
    elif black != "0": unknown.append("Sui: assenza di blacklist non verificata")
    for key in ("mintable", "contract_upgradeable", "metadata_modifiable"):
        s = status(token.get(key), "value")
        if s in {"1", "2"}: warnings.append(f"Sui: {key} attivo")
        elif s != "0": warnings.append(f"Sui: {key} non ancora verificato")
    if settings["security_mode"] == "strict":
        for key in ("mintable", "contract_upgradeable"):
            s = status(token.get(key), "value")
            if s in {"1", "2"}: blocked.append(f"Sui: {key} non ammesso in modalità prudente")
            elif s != "0": unknown.append(f"Sui: {key} essenziale in modalità prudente")
    warnings.append("Sui: nessuna simulazione di vendita, liquidità e routing non verificati")
    return blocked, unknown, warnings


async def check_non_evm(guard, session, kind, address, settings):
    if kind == "solana": return await check_solana(guard, session, address, settings)
    coin = await resolve_sui(guard, session, address)
    if not coin: return SecurityResult("unknown", ["Sui: package ambiguo/non risolvibile; serve package::modulo::TOKEN"], "sui")
    payload = await guard._get(session, "https://api.gopluslabs.io/api/v1/sui/token_security", {"contract_addresses": coin})
    tokens = payload.get("result") or {} if payload.get("code") == 1 else {}
    token = next((v for k, v in tokens.items() if canonical_sui(k) == coin), None)
    b, u, w = sui_scanner(token, settings)
    return finish(b, u, w, "sui", {"coin_type": coin, "forward_address": coin,
                                   "goplus": {k: token.get(k) for k in ("blacklist", "mintable", "contract_upgradeable", "metadata_modifiable")} if token else {}})
