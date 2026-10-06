import asyncio
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web
from telethon import TelegramClient, events
from telethon.errors import FloodWaitError
from telethon.sessions import StringSession
from telethon.utils import get_peer_id

from token_security import DEFAULT_SETTINGS, TokenSecurity, validate_settings
from non_evm_security import canonical_sui, valid_mint

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("tg-contract-forwarder")

REQUIRED_VARS = [
    "TELEGRAM_API_ID",
    "TELEGRAM_API_HASH",
    "TELEGRAM_SESSION_STRING",
    "SOURCE_CHAT",
    "DESTINATION_BOT",
]

PATTERNS = {
    "sui": re.compile(r"(?<![0-9a-fA-F])(?:0x[a-fA-F0-9]{1,64}::[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*|0x[a-fA-F0-9]{64})(?![0-9a-fA-F])"),
    "evm": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])"),
    "solana": re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])"),
}
ALLOWED_ADDRESS_TYPES = {"evm", "solana", "sui"}
ALLOWED_EVENT_ACTIONS = {"forwarded", "duplicate_ignored", "dry_run", "error",
                         "security_blocked", "security_unknown", "security_test", "stale_ignored", "unsupported_destination"}


def parse_peer(value: str):
    value = value.strip()
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def normalize_address(address: str) -> str:
    if "::" in address:
        return canonical_sui(address) or address
    return address.lower() if address.startswith("0x") else address


async def wait_for_configuration():
    missing = [name for name in REQUIRED_VARS if not os.getenv(name, "").strip()]
    if not missing:
        return
    log.warning("Configuration incomplete. Missing Railway variables: %s", ", ".join(missing))
    while True:
        await asyncio.sleep(3600)


def open_db(path: str):
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS forwarded_contracts (
            address TEXT PRIMARY KEY,
            chain_type TEXT NOT NULL,
            forwarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS bot_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS ca_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            chain_type TEXT,
            address TEXT,
            action TEXT NOT NULL,
            detail TEXT,
            source_chat TEXT,
            destination_bot TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_ca_events_event_at ON ca_events(event_at DESC, id DESC)"
    )
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(ca_events)")}
    if "security_json" not in columns:
        connection.execute("ALTER TABLE ca_events ADD COLUMN security_json TEXT")
    connection.commit()
    return connection


def setting_get(db, key: str, fallback: str) -> str:
    row = db.execute("SELECT value FROM bot_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else fallback


def setting_set(db, key: str, value: str):
    db.execute(
        """
        INSERT INTO bot_settings(key, value, updated_at)
        VALUES(?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, value),
    )


def save_config(db, config: dict):
    setting_set(db, "source_chat", config["source_chat_raw"])
    setting_set(db, "destination_bot", config["destination_raw"])
    setting_set(db, "dry_run", "true" if config["dry_run"] else "false")
    setting_set(db, "forward_delay_seconds", str(config["forward_delay_seconds"]))
    setting_set(db, "address_types", ",".join(sorted(config["address_types"])))
    for key in DEFAULT_SETTINGS:
        setting_set(db, key, str(config[key]))
    db.commit()


def migrate_evidence_policy(db):
    """Apply the user's requested preset once; subsequent panel edits persist."""
    if setting_get(db, "evidence_policy_v3", "") == "applied": return
    for key, value in {"forward_delay_seconds": "1", "security_mode": "balanced",
                       "security_timeout_seconds": "2.5", "security_chain": "auto"}.items():
        setting_set(db, key, value)
    setting_set(db, "evidence_policy_v3", "applied")
    db.commit()


def identify_token(address):
    address = address.strip()
    if canonical_sui(address) or re.fullmatch(r"0x[0-9a-fA-F]{64}", address): return "sui"
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", address): return "evm"
    if valid_mint(address): return "solana"
    raise ValueError("Inserisci un indirizzo token valido o il tipo completo della coin Sui")


def load_saved_config(db) -> dict:
    env_types = os.getenv("ADDRESS_TYPES", "evm,solana,sui")
    address_types = {
        item.strip().lower()
        for item in setting_get(db, "address_types", env_types).split(",")
        if item.strip().lower() in ALLOWED_ADDRESS_TYPES
    }
    if not address_types:
        address_types = {"evm", "solana", "sui"}

    dry_raw = setting_get(db, "dry_run", os.getenv("DRY_RUN", "true"))
    delay_raw = setting_get(db, "forward_delay_seconds", os.getenv("FORWARD_DELAY_SECONDS", "1"))

    try:
        delay = max(0.0, min(30.0, float(delay_raw)))
    except ValueError:
        delay = 1.0

    security_settings = validate_settings({key: setting_get(db, key, str(value))
                                           for key, value in DEFAULT_SETTINGS.items()})
    return {
        "source_chat_raw": setting_get(db, "source_chat", os.environ["SOURCE_CHAT"]).strip(),
        "destination_raw": setting_get(db, "destination_bot", os.environ["DESTINATION_BOT"]).strip(),
        "dry_run": dry_raw.lower() in {"1", "true", "yes", "on"},
        "forward_delay_seconds": delay,
        "address_types": address_types,
        **security_settings,
    }


def is_forwarded(db, address: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM forwarded_contracts WHERE address = ? LIMIT 1",
        (normalize_address(address),),
    ).fetchone()
    return row is not None


def mark_forwarded(db, kind: str, address: str):
    db.execute(
        "INSERT OR IGNORE INTO forwarded_contracts(address, chain_type) VALUES(?, ?)",
        (normalize_address(address), kind),
    )
    db.commit()


def forwarded_count(db) -> int:
    row = db.execute("SELECT COUNT(*) AS n FROM forwarded_contracts").fetchone()
    return int(row["n"])


def add_event(
    db,
    action: str,
    kind: str | None,
    address: str | None,
    source_chat: str,
    destination_bot: str,
    detail: str | None = None,
    security: dict | None = None,
):
    if action not in ALLOWED_EVENT_ACTIONS:
        action = "error"
    db.execute(
        """
        INSERT INTO ca_events(chain_type, address, action, detail, source_chat, destination_bot, security_json)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            kind,
            normalize_address(address) if address else None,
            action,
            detail[:500] if detail else None,
            source_chat,
            destination_bot,
            json.dumps(security, ensure_ascii=False) if security else None,
        ),
    )
    db.commit()


def recent_events(db, limit: int = 50):
    limit = max(1, min(200, int(limit)))
    rows = db.execute(
        """
        SELECT id, event_at, chain_type, address, action, detail, source_chat, destination_bot, security_json
        FROM ca_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        raw = item.pop("security_json")
        item["security"] = json.loads(raw) if raw else None
        events.append(item)
    return events


async def screen_contract(db, guard, runtime, config, kind, address):
    """The only pre-send gate; unknown results never authorize a send."""
    report = await guard.check(kind, address, config)
    runtime["last_security"] = report.public()
    if not report.allowed:
        action = "security_blocked" if report.verdict == "blocked" else "security_unknown"
        runtime["last_action"] = action
        add_event(db, action, kind, address, config["source_chat_raw"],
                  config["destination_raw"], report.detail(), report.public())
        log.warning("Security prevented forwarding %s: %s", address, report.detail())
    return report


def extract_first_contract(text: str, enabled_types: set[str]):
    candidates = []
    for kind in ("sui", "evm", "solana"):
        if kind not in enabled_types:
            continue
        for match in PATTERNS[kind].finditer(text):
            candidates.append((match.start(), kind, match.group(0)))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (item[0], -len(item[2])))
    _, kind, address = candidates[0]
    return kind, address


LOGIN_HTML = """<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CA Courier • Login</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 20% 20%,#23356f 0,transparent 36%),radial-gradient(circle at 80% 10%,#743d89 0,transparent 34%),#0b1020;color:#edf1ff;padding:24px}.card{width:min(430px,100%);background:rgba(18,24,48,.86);border:1px solid rgba(255,255,255,.11);border-radius:28px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.38);backdrop-filter:blur(16px)}.bot{width:72px;height:72px;border-radius:22px;display:grid;place-items:center;font-size:34px;background:linear-gradient(145deg,#88a7ff,#bd83ff);box-shadow:0 12px 34px rgba(112,116,255,.32);margin-bottom:22px}h1{font-size:30px;margin:0 0 8px}.sub{color:#aeb8d9;line-height:1.5;margin:0 0 26px}label{display:block;font-size:13px;color:#b8c1df;margin-bottom:8px;font-weight:700}input{width:100%;border:1px solid #344064;background:#0d1429;color:#fff;padding:15px 16px;border-radius:15px;outline:none;font-size:16px}input:focus{border-color:#8da7ff;box-shadow:0 0 0 4px rgba(126,151,255,.12)}button{width:100%;border:0;border-radius:15px;padding:15px;font-size:15px;font-weight:800;margin-top:15px;background:linear-gradient(135deg,#8ea8ff,#b87cff);color:#11172d;cursor:pointer}.err{background:rgba(255,103,122,.12);border:1px solid rgba(255,103,122,.25);color:#ffb2bd;padding:11px 13px;border-radius:13px;margin-bottom:15px;font-size:13px}.tiny{margin-top:18px;text-align:center;color:#727eaa;font-size:12px}</style></head>
<body><form class="card" method="post" action="/login"><div class="bot">🤖</div><h1>CA Courier</h1><p class="sub">Il piccolo corriere dei contract address. Accesso al pannello di controllo.</p>{error}<label>Password pannello</label><input type="password" name="password" autocomplete="current-password" autofocus placeholder="••••••••••••"><button type="submit">Apri il pannello ✨</button><div class="tiny">Railway • Telegram listener • Persistent history</div></form></body></html>"""


async def main():
    await wait_for_configuration()

    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"].strip()
    session_string = os.environ["TELEGRAM_SESSION_STRING"].strip()
    source_sender_raw = os.getenv("SOURCE_SENDER", "").strip()
    require_keyword = os.getenv("REQUIRE_KEYWORD", "").strip().lower()
    db_path = os.getenv("HISTORY_DB_PATH", "/data/forwarded_contracts.sqlite3")
    panel_password = os.getenv("PANEL_PASSWORD", "").strip()
    panel_secret = os.getenv("PANEL_SECRET", "").strip()
    port = int(os.getenv("PORT", "8080"))

    db = open_db(db_path)
    migrate_evidence_policy(db)
    config_lock = asyncio.Lock()
    processing_lock = asyncio.Lock()
    security_test_lock = asyncio.Lock()
    security_guard = TokenSecurity()
    runtime = {
        "config": load_saved_config(db),
        "source_chat_id": None,
        "destination_entity": None,
        "status": "starting",
        "last_address": None,
        "last_chain": None,
        "last_action": None,
        "last_event_at": None,
        "last_error": None,
        "last_security": None,
        "config_revision": 0,
    }

    source_sender = parse_peer(source_sender_raw) if source_sender_raw else None

    client = TelegramClient(
        StringSession(session_string),
        api_id,
        api_hash,
        connection_retries=None,
        retry_delay=3,
        auto_reconnect=True,
    )
    await client.start()
    me = await client.get_me()

    async def resolve_runtime_config(candidate: dict):
        source_entity = await client.get_entity(parse_peer(candidate["source_chat_raw"]))
        destination_entity = await client.get_entity(parse_peer(candidate["destination_raw"]))
        return get_peer_id(source_entity), destination_entity

    async def apply_runtime_config(candidate: dict, persist: bool):
        source_chat_id, destination_entity = await resolve_runtime_config(candidate)
        async with config_lock:
            runtime["config"] = {
                "source_chat_raw": candidate["source_chat_raw"],
                "destination_raw": candidate["destination_raw"],
                "dry_run": bool(candidate["dry_run"]),
                "forward_delay_seconds": float(candidate["forward_delay_seconds"]),
                "address_types": set(candidate["address_types"]),
                **validate_settings(candidate),
            }
            runtime["source_chat_id"] = source_chat_id
            runtime["destination_entity"] = destination_entity
            runtime["last_error"] = None
            runtime["config_revision"] += 1
            if persist:
                save_config(db, runtime["config"])

    await apply_runtime_config(runtime["config"], persist=False)
    runtime["status"] = "online"

    log.info(
        "Logged in as %s (%s)",
        getattr(me, "username", None) or getattr(me, "first_name", "unknown"),
        me.id,
    )
    log.info(
        "Listening source=%s destination=%s address_types=%s dry_run=%s delay=%ss history=%s",
        runtime["config"]["source_chat_raw"],
        runtime["config"]["destination_raw"],
        ",".join(sorted(runtime["config"]["address_types"])),
        runtime["config"]["dry_run"],
        runtime["config"]["forward_delay_seconds"],
        db_path,
    )

    @client.on(events.NewMessage)
    async def on_new_message(event):
        kind = None
        address = None
        config_snapshot = None
        try:
            if event.chat_id != runtime["source_chat_id"]:
                return

            text = event.raw_text or ""
            if not text:
                return

            if source_sender is not None:
                sender = await event.get_sender()
                sender_id = getattr(sender, "id", None)
                sender_username = getattr(sender, "username", None)
                if isinstance(source_sender, int):
                    if sender_id != source_sender:
                        return
                else:
                    wanted = str(source_sender).lstrip("@").lower()
                    if not sender_username or sender_username.lower() != wanted:
                        return

            if require_keyword and require_keyword not in text.lower():
                return

            config_snapshot = runtime["config"].copy()
            revision_snapshot = runtime["config_revision"]
            received_at = asyncio.get_running_loop().time()
            config_snapshot["address_types"] = set(runtime["config"]["address_types"])
            destination_entity_snapshot = runtime["destination_entity"]

            result = extract_first_contract(text, config_snapshot["address_types"])
            if not result:
                return

            kind, address = result

            async with processing_lock:
                now = datetime.now(timezone.utc).isoformat()
                runtime["last_address"] = address
                runtime["last_chain"] = kind
                runtime["last_event_at"] = now
                runtime["last_error"] = None
                runtime["last_security"] = None

                if is_forwarded(db, address):
                    runtime["last_action"] = "duplicate_ignored"
                    add_event(
                        db,
                        "duplicate_ignored",
                        kind,
                        address,
                        config_snapshot["source_chat_raw"],
                        config_snapshot["destination_raw"],
                    )
                    log.info("Duplicate ignored: %s", address)
                    return

                log.info("Detected %s contract: %s", kind, address)
                screening_started = asyncio.get_running_loop().time()

                def still_current():
                    return (revision_snapshot == runtime["config_revision"] and
                            asyncio.get_running_loop().time() - received_at <= 120)

                def record_stale():
                    runtime["last_action"] = "stale_ignored"
                    add_event(db, "stale_ignored", kind, address,
                              config_snapshot["source_chat_raw"], config_snapshot["destination_raw"],
                              "Configurazione cambiata o messaggio in attesa da oltre 120 secondi")

                if not still_current():
                    record_stale()
                    return
                security_report = await screen_contract(db, security_guard, runtime, config_snapshot, kind, address)
                if not security_report.allowed:
                    return
                remaining_delay = config_snapshot["forward_delay_seconds"] - (asyncio.get_running_loop().time() - screening_started)
                if remaining_delay > 0:
                    await asyncio.sleep(remaining_delay)
                if not still_current():
                    record_stale()
                    return

                detected_address = address
                address = security_report.checks.get("forward_address", address)
                runtime["last_address"] = address
                if is_forwarded(db, address):
                    runtime["last_action"] = "duplicate_ignored"
                    add_event(db, "duplicate_ignored", kind, address, config_snapshot["source_chat_raw"],
                              config_snapshot["destination_raw"])
                    return
                if kind == "sui" and config_snapshot["destination_raw"].lstrip("@").lower().startswith("maestro"):
                    runtime["last_action"] = "unsupported_destination"
                    add_event(db, "unsupported_destination", kind, address, config_snapshot["source_chat_raw"],
                              config_snapshot["destination_raw"], "Maestro non supporta Sui: nessun inoltro",
                              security_report.public())
                    return

                if config_snapshot["dry_run"]:
                    runtime["last_action"] = "dry_run"
                    add_event(
                        db,
                        "dry_run",
                        kind,
                        address,
                        config_snapshot["source_chat_raw"],
                        config_snapshot["destination_raw"],
                        security_report.detail(),
                        security_report.public(),
                    )
                    log.info(
                        "[DRY_RUN] Would send to %s: %s",
                        config_snapshot["destination_raw"],
                        address,
                    )
                    return

                try:
                    sent = await client.send_message(destination_entity_snapshot, address)
                except FloodWaitError as exc:
                    log.warning("Telegram FloodWait: %ss", exc.seconds)
                    await asyncio.sleep(exc.seconds + 1)
                    if not still_current():
                        record_stale()
                        return
                    # Never reuse a positive result after a Telegram rate-limit wait.
                    security_report = await screen_contract(db, security_guard, runtime, config_snapshot, kind, address)
                    if not security_report.allowed:
                        return
                    if not still_current():
                        record_stale()
                        return
                    sent = await client.send_message(destination_entity_snapshot, address)

                mark_forwarded(db, kind, address)
                if detected_address != address:
                    mark_forwarded(db, kind, detected_address)
                add_event(
                    db,
                    "forwarded",
                    kind,
                    address,
                    config_snapshot["source_chat_raw"],
                    config_snapshot["destination_raw"],
                    f"message_id={sent.id}",
                    security_report.public(),
                )
                runtime["last_action"] = "forwarded"
                log.info("Forwarded successfully, message_id=%s", sent.id)

        except Exception as exc:
            runtime["last_error"] = str(exc)
            runtime["last_action"] = "error"
            runtime["last_event_at"] = datetime.now(timezone.utc).isoformat()
            if address and config_snapshot:
                add_event(
                    db,
                    "error",
                    kind,
                    address,
                    config_snapshot["source_chat_raw"],
                    config_snapshot["destination_raw"],
                    str(exc),
                )
            log.exception("Error processing Telegram message")

    def is_authenticated(request):
        return bool(panel_secret) and request.cookies.get("ca_panel") == panel_secret

    async def login_get(request):
        if is_authenticated(request):
            raise web.HTTPFound("/")
        return web.Response(text=LOGIN_HTML.format(error=""), content_type="text/html")

    async def login_post(request):
        data = await request.post()
        if not panel_password:
            return web.Response(
                text=LOGIN_HTML.format(
                    error='<div class="err">PANEL_PASSWORD non configurata su Railway.</div>'
                ),
                content_type="text/html",
                status=503,
            )
        if data.get("password", "") != panel_password:
            return web.Response(
                text=LOGIN_HTML.format(
                    error='<div class="err">Password non corretta. Riprova 👀</div>'
                ),
                content_type="text/html",
                status=401,
            )
        response = web.HTTPFound("/")
        response.set_cookie(
            "ca_panel",
            panel_secret,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=60 * 60 * 24 * 30,
        )
        return response

    async def logout_post(request):
        response = web.HTTPFound("/login")
        response.del_cookie("ca_panel")
        return response

    async def panel_get(request):
        if not is_authenticated(request):
            raise web.HTTPFound("/login")
        panel_path = Path(__file__).with_name("panel.html")
        return web.Response(
            text=panel_path.read_text(encoding="utf-8"),
            content_type="text/html",
        )

    async def api_config_get(request):
        if not is_authenticated(request):
            raise web.HTTPUnauthorized()
        cfg = runtime["config"]
        return web.json_response(
            {
                "source_chat": cfg["source_chat_raw"],
                "destination_bot": cfg["destination_raw"],
                "dry_run": cfg["dry_run"],
                "forward_delay_seconds": cfg["forward_delay_seconds"],
                "address_types": sorted(cfg["address_types"]),
                "status": runtime["status"],
                "telegram_user": getattr(me, "username", None)
                or getattr(me, "first_name", "unknown"),
                "forwarded_count": forwarded_count(db),
                "last_address": runtime["last_address"],
                "last_chain": runtime["last_chain"],
                "last_action": runtime["last_action"],
                "last_event_at": runtime["last_event_at"],
                "last_error": runtime["last_error"],
                "last_security": runtime["last_security"],
                "security_enabled": True,
                **{key: cfg[key] for key in DEFAULT_SETTINGS},
            }
        )

    async def api_config_post(request):
        if not is_authenticated(request):
            raise web.HTTPUnauthorized()
        try:
            payload = await request.json()
            source_chat = str(payload.get("source_chat", "")).strip()
            destination_bot = str(payload.get("destination_bot", "")).strip()
            dry_run = bool(payload.get("dry_run", False))
            delay = float(payload.get("forward_delay_seconds", 0))
            types_raw = payload.get("address_types", [])
            address_types = {
                str(item).strip().lower()
                for item in types_raw
                if str(item).strip().lower() in ALLOWED_ADDRESS_TYPES
            }

            if not source_chat:
                raise ValueError("Inserisci una sorgente Telegram.")
            if not destination_bot:
                raise ValueError("Inserisci una destinazione Telegram.")
            if not 0 <= delay <= 30:
                raise ValueError("Il delay deve essere compreso tra 0 e 30 secondi.")
            if not address_types:
                raise ValueError("Seleziona almeno un tipo di address.")

            candidate = {
                "source_chat_raw": source_chat,
                "destination_raw": destination_bot,
                "dry_run": dry_run,
                "forward_delay_seconds": delay,
                "address_types": address_types,
                **validate_settings({key: payload.get(key, runtime["config"][key])
                                     for key in DEFAULT_SETTINGS}),
            }

            await apply_runtime_config(candidate, persist=True)
            log.info(
                "Panel config updated: source=%s destination=%s dry_run=%s delay=%s address_types=%s",
                source_chat,
                destination_bot,
                dry_run,
                delay,
                ",".join(sorted(address_types)),
            )
            return web.json_response({"ok": True})
        except Exception as exc:
            runtime["last_error"] = str(exc)
            return web.json_response({"ok": False, "error": str(exc)}, status=400)

    async def api_history_get(request):
        if not is_authenticated(request):
            raise web.HTTPUnauthorized()
        try:
            limit = int(request.query.get("limit", "50"))
        except ValueError:
            limit = 50
        return web.json_response(
            {
                "events": recent_events(db, limit),
                "forwarded_count": forwarded_count(db),
            }
        )

    async def api_security_check(request):
        if not is_authenticated(request):
            raise web.HTTPUnauthorized()
        if security_test_lock.locked():
            return web.json_response({"error": "Verifica già in corso"}, status=429)
        async with security_test_lock:
            try:
                payload = await request.json()
                address = str(payload.get("address", "")).strip()
                kind = identify_token(address)
                if len(address) > 512:
                    raise ValueError("Indirizzo o tipo non valido")
                cfg = runtime["config"].copy()
                report = await security_guard.check(kind, address, cfg)
                add_event(db, "security_test", kind, address, cfg["source_chat_raw"],
                          cfg["destination_raw"], report.detail(), report.public())
                return web.json_response({**report.public(), "kind": kind})
            except (ValueError, TypeError):
                return web.json_response({"error": "Richiesta non valida"}, status=400)

    async def health_get(request):
        return web.json_response({"ok": True, "bot": runtime["status"],
                                  "version": "security-gate-v3", "security_enabled": True,
                                  "security_fail_closed": runtime["config"]["security_mode"] == "strict",
                                  "forward_delay_seconds": runtime["config"]["forward_delay_seconds"],
                                  "security_timeout_seconds": runtime["config"]["security_timeout_seconds"],
                                  "security_chain": runtime["config"]["security_chain"],
                                  "security_mode": runtime["config"]["security_mode"],
                                  "security_chains": ["evm", "solana", "sui"]})

    app = web.Application(client_max_size=64 * 1024)
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_post("/logout", logout_post)
    app.router.add_get("/", panel_get)
    app.router.add_get("/api/config", api_config_get)
    app.router.add_post("/api/config", api_config_post)
    app.router.add_get("/api/history", api_history_get)
    app.router.add_post("/api/security/check", api_security_check)
    app.router.add_get("/health", health_get)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info("Control panel listening on port %s", port)
    log.info("Userbot running")

    try:
        await client.run_until_disconnected()
    finally:
        runtime["status"] = "offline"
        await runner.cleanup()
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
