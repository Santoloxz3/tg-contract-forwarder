import asyncio
import logging
import os
import re
from collections import deque

from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("tg-contract-forwarder")

REQUIRED_VARS = [
    "TELEGRAM_API_ID",
    "TELEGRAM_API_HASH",
    "TELEGRAM_SESSION_STRING",
    "SOURCE_CHAT",
    "DESTINATION_BOT",
]

PATTERNS = {
    "evm": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])"),
    "sui": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{64}(?![0-9a-fA-F])"),
    "solana": re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])"),
}


def parse_peer(value: str):
    value = value.strip()
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


async def wait_for_configuration():
    missing = [name for name in REQUIRED_VARS if not os.getenv(name, "").strip()]
    if not missing:
        return False
    log.warning("Configuration incomplete. Missing Railway variables: %s", ", ".join(missing))
    log.warning("Service is online but idle. Add the missing variables in Railway to activate it.")
    while True:
        await asyncio.sleep(3600)


async def main():
    await wait_for_configuration()

    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"].strip()
    session_string = os.environ["TELEGRAM_SESSION_STRING"].strip()
    source_chat_raw = os.environ["SOURCE_CHAT"].strip()
    source_sender_raw = os.getenv("SOURCE_SENDER", "").strip()
    destination_raw = os.environ["DESTINATION_BOT"].strip()

    address_types = {x.strip().lower() for x in os.getenv("ADDRESS_TYPES", "evm").split(",") if x.strip()}
    require_keyword = os.getenv("REQUIRE_KEYWORD", "").strip().lower()
    dry_run = os.getenv("DRY_RUN", "true").lower() in {"1", "true", "yes", "on"}
    forward_delay_seconds = float(os.getenv("FORWARD_DELAY_SECONDS", "0"))
    max_recent_addresses = int(os.getenv("MAX_RECENT_ADDRESSES", "500"))

    recent_queue = deque(maxlen=max_recent_addresses)
    recent_set = set()

    def extract_addresses(text: str):
        out = []
        seen = set()
        for kind in address_types:
            pattern = PATTERNS.get(kind)
            if not pattern:
                log.warning("Unknown ADDRESS_TYPES value ignored: %s", kind)
                continue
            for match in pattern.findall(text):
                key = match.lower() if match.startswith("0x") else match
                if key not in seen:
                    seen.add(key)
                    out.append((kind, match))
        return out

    def already_sent(address: str) -> bool:
        key = address.lower() if address.startswith("0x") else address
        return key in recent_set

    def remember_sent(address: str):
        key = address.lower() if address.startswith("0x") else address
        if key in recent_set:
            return
        if len(recent_queue) == recent_queue.maxlen and recent_queue:
            recent_set.discard(recent_queue[0])
        recent_queue.append(key)
        recent_set.add(key)

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
    log.info("Logged in as %s (%s)", getattr(me, "username", None) or getattr(me, "first_name", "unknown"), me.id)
    log.info(
        "Listening source=%s sender=%s destination=%s address_types=%s dry_run=%s",
        source_chat_raw,
        source_sender_raw or "ANY",
        destination_raw,
        ",".join(sorted(address_types)),
        dry_run,
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

            for kind, address in extract_addresses(text):
                if already_sent(address):
                    log.info("Duplicate ignored: %s", address)
                    continue

                log.info("Detected %s contract: %s", kind, address)

                if forward_delay_seconds > 0:
                    await asyncio.sleep(forward_delay_seconds)

                if dry_run:
                    log.info("[DRY_RUN] Would send to %s: %s", destination_raw, address)
                    remember_sent(address)
                    continue

                try:
                    sent = await client.send_message(destination, address)
                except FloodWaitError as e:
                    log.warning("FloodWait %ss", e.seconds)
                    await asyncio.sleep(e.seconds + 1)
                    sent = await client.send_message(destination, address)

                remember_sent(address)
                log.info("Sent successfully, message_id=%s", sent.id)

        except Exception:
            log.exception("Error processing Telegram message")

    log.info("Userbot running")
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
