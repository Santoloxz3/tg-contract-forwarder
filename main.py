import asyncio
import logging
import os
import re
from collections import deque

from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

API_ID = int(os.environ["TELEGRAM_API_ID"])
API_HASH = os.environ["TELEGRAM_API_HASH"].strip()
SESSION_STRING = os.environ["TELEGRAM_SESSION_STRING"].strip()
SOURCE_CHAT = os.environ["SOURCE_CHAT"].strip()
SOURCE_SENDER = os.getenv("SOURCE_SENDER", "").strip()
DESTINATION_BOT = os.environ["DESTINATION_BOT"].strip()
ADDRESS_TYPES = {x.strip().lower() for x in os.getenv("ADDRESS_TYPES", "evm").split(",") if x.strip()}
REQUIRE_KEYWORD = os.getenv("REQUIRE_KEYWORD", "").strip().lower()
DRY_RUN = os.getenv("DRY_RUN", "true").lower() in {"1", "true", "yes", "on"}
FORWARD_DELAY_SECONDS = float(os.getenv("FORWARD_DELAY_SECONDS", "0"))
MAX_RECENT_ADDRESSES = int(os.getenv("MAX_RECENT_ADDRESSES", "500"))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("tg-contract-forwarder")

PATTERNS = {
    "evm": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])"),
    "sui": re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{64}(?![0-9a-fA-F])"),
    "solana": re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])"),
}

recent_queue = deque(maxlen=MAX_RECENT_ADDRESSES)
recent_set = set()


def parse_peer(value: str):
    value = value.strip()
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def extract_addresses(text: str):
    out = []
    seen = set()
    for kind in ADDRESS_TYPES:
        pattern = PATTERNS.get(kind)
        if not pattern:
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


async def main():
    source_chat = parse_peer(SOURCE_CHAT)
    source_sender = parse_peer(SOURCE_SENDER) if SOURCE_SENDER else None
    destination = parse_peer(DESTINATION_BOT)

    client = TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH, connection_retries=None, retry_delay=3, auto_reconnect=True)
    await client.start()
    me = await client.get_me()
    log.info("Logged in as %s (%s)", getattr(me, "username", None) or getattr(me, "first_name", "unknown"), me.id)
    log.info("Listening on source=%s sender=%s destination=%s dry_run=%s", SOURCE_CHAT, SOURCE_SENDER or "ANY", DESTINATION_BOT, DRY_RUN)

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

            if REQUIRE_KEYWORD and REQUIRE_KEYWORD not in text.lower():
                return

            for kind, address in extract_addresses(text):
                if already_sent(address):
                    log.info("Duplicate ignored: %s", address)
                    continue

                log.info("Detected %s contract: %s", kind, address)
                if FORWARD_DELAY_SECONDS > 0:
                    await asyncio.sleep(FORWARD_DELAY_SECONDS)

                if DRY_RUN:
                    log.info("[DRY_RUN] Would send to %s: %s", DESTINATION_BOT, address)
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
