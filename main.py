import asyncio
import logging
import os
import re
import sqlite3
from pathlib import Path

from telethon import TelegramClient, events
from telethon.errors import FloodWaitError
from telethon.sessions import StringSession

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

# Order matters: longer 0x addresses are checked before EVM addresses.
PATTERNS = {
    "sui": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{64}(?![0-9a-fA-F])"),
    "evm": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])"),
    "solana": re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])"),
}


def parse_peer(value: str):
    value = value.strip()
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def normalize_address(address: str) -> str:
    return address.lower() if address.startswith("0x") else address


async def wait_for_configuration():
    missing = [name for name in REQUIRED_VARS if not os.getenv(name, "").strip()]
    if not missing:
        return
    log.warning("Configuration incomplete. Missing Railway variables: %s", ", ".join(missing))
    while True:
        await asyncio.sleep(3600)


def open_history_db(path: str):
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS forwarded_contracts (
            address TEXT PRIMARY KEY,
            chain_type TEXT NOT NULL,
            forwarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.commit()
    return connection


def is_forwarded(db, address: str) -> bool:
    key = normalize_address(address)
    row = db.execute(
        "SELECT 1 FROM forwarded_contracts WHERE address = ? LIMIT 1", (key,)
    ).fetchone()
    return row is not None


def mark_forwarded(db, kind: str, address: str):
    key = normalize_address(address)
    db.execute(
        "INSERT OR IGNORE INTO forwarded_contracts(address, chain_type) VALUES(?, ?)",
        (key, kind),
    )
    db.commit()


def extract_first_contract(text: str, enabled_types: set[str]):
    candidates = []
    for kind in ("sui", "evm", "solana"):
        if kind not in enabled_types:
            continue
        for match in PATTERNS[kind].finditer(text):
            candidates.append((match.start(), kind, match.group(0)))

    if not candidates:
        return None

    # If patterns ever overlap, prefer the earliest match, then the longer address.
    candidates.sort(key=lambda item: (item[0], -len(item[2])))
    _, kind, address = candidates[0]
    return kind, address


async def main():
    await wait_for_configuration()

    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"].strip()
    session_string = os.environ["TELEGRAM_SESSION_STRING"].strip()
    source_chat_raw = os.environ["SOURCE_CHAT"].strip()
    source_sender_raw = os.getenv("SOURCE_SENDER", "").strip()
    destination_raw = os.environ["DESTINATION_BOT"].strip()

    address_types = {
        item.strip().lower()
        for item in os.getenv("ADDRESS_TYPES", "evm,solana,sui").split(",")
        if item.strip()
    }
    require_keyword = os.getenv("REQUIRE_KEYWORD", "").strip().lower()
    dry_run = os.getenv("DRY_RUN", "true").lower() in {"1", "true", "yes", "on"}
    forward_delay_seconds = max(0.0, float(os.getenv("FORWARD_DELAY_SECONDS", "2")))
    history_db_path = os.getenv("HISTORY_DB_PATH", "/data/forwarded_contracts.sqlite3")

    db = open_history_db(history_db_path)
    processing_lock = asyncio.Lock()

    source_chat = parse_peer(source_chat_raw)
    source_sender = parse_peer(source_sender_raw) if source_sender_raw else None
    destination = parse_peer(destination_raw)

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
    await client.get_entity(source_chat)
    await client.get_entity(destination)

    log.info(
        "Logged in as %s (%s)",
        getattr(me, "username", None) or getattr(me, "first_name", "unknown"),
        me.id,
    )
    log.info(
        "Listening source=%s sender=%s destination=%s address_types=%s dry_run=%s delay=%ss history=%s",
        source_chat_raw,
        source_sender_raw or "ANY",
        destination_raw,
        ",".join(sorted(address_types)),
        dry_run,
        forward_delay_seconds,
        history_db_path,
    )

    @client.on(events.NewMessage(chats=source_chat))
    async def on_new_message(event):
        try:
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

            result = extract_first_contract(text, address_types)
            if not result:
                return

            kind, address = result

            async with processing_lock:
                if is_forwarded(db, address):
                    log.info("Duplicate ignored: %s", address)
                    return

                log.info("Detected %s contract: %s", kind, address)

                if forward_delay_seconds:
                    await asyncio.sleep(forward_delay_seconds)

                if dry_run:
                    log.info("[DRY_RUN] Would send to %s: %s", destination_raw, address)
                    return

                try:
                    sent = await client.send_message(destination, address)
                except FloodWaitError as exc:
                    log.warning("Telegram FloodWait: %ss", exc.seconds)
                    await asyncio.sleep(exc.seconds + 1)
                    sent = await client.send_message(destination, address)

                mark_forwarded(db, kind, address)
                log.info("Forwarded successfully, message_id=%s", sent.id)

        except Exception:
            log.exception("Error processing Telegram message")

    log.info("Userbot running")
    try:
        await client.run_until_disconnected()
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
