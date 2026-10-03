import os
from telethon import TelegramClient
from telethon.sessions import StringSession

api_id = int(os.environ["TELEGRAM_API_ID"])
api_hash = os.environ["TELEGRAM_API_HASH"].strip()

print("Telegram login: enter your phone number, login code and 2FA password if enabled.")
print("The generated session string is sensitive: keep it private.\n")

with TelegramClient(StringSession(), api_id, api_hash) as client:
    print("\nTELEGRAM_SESSION_STRING=\n")
    print(client.session.save())
