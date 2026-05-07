#!/usr/bin/env python3
"""
Interactive Rubika File Uploader
Uploads any file to your Rubika "Saved Messages" with a progress bar.
Based on the proven authentication logic from rubika_auth_helper.py.
"""

import asyncio
import os
import re
import sys

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from rubpy import Client
from rubpy.crypto import Crypto


# ----------------------------------------------------------------------
# Helper: normalise a phone number (as in the original auth helper)
# ----------------------------------------------------------------------
def normalize_phone(phone: str) -> str:
    """Convert any common phone format into the Rubika‑expected format."""
    phone = phone.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    # Remove leading + or 00
    match = re.match(r"^(?:\+|00)?(\d{7,15})$", phone)
    if not match:
        raise ValueError("Invalid phone number.")
    n = match.group(1)
    if n.startswith("0"):
        n = f"98{n[1:]}"
    elif n.startswith("9") and len(n) == 10:
        n = f"98{n}"
    return n


# ----------------------------------------------------------------------
# Helper: test if the session is already authorised
# ----------------------------------------------------------------------
async def is_authorized(client: Client) -> bool:
    try:
        await client.get_me()
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------
# Authentication (interactive login if needed)
# ----------------------------------------------------------------------
async def get_client(session_file: str = "rubika.session") -> Client:
    client = Client(session_file)
    await client.connect()

    if await is_authorized(client):
        return client

    # ---------- Interactive login ----------
    print("\n🔐 No valid session found. Let's log in to Rubika.\n")
    raw_phone = input("📱 Enter your phone number (include country code, e.g. +98912...): ").strip()
    if not raw_phone:
        raise ValueError("Phone number is required.")
    phone = normalize_phone(raw_phone)

    # 1) Send the verification code
    send_result = await client.send_code(phone_number=phone, send_type="SMS")

    # 2) Check if a two‑step verification password is needed
    if getattr(send_result, "status", "") == "SendPassKey":
        hint = getattr(send_result, "hint_pass_key", "") or ""
        print(f"\n🔑 Two‑step verification is enabled. Hint: {hint}")
        pass_key = input("Password: ").strip()
        if not pass_key:
            raise ValueError("Password is required.")
        send_result = await client.send_code(phone_number=phone, pass_key=pass_key)

    # 3) Make sure we actually got the OTP token
    phone_code_hash = getattr(send_result, "phone_code_hash", None)
    if not phone_code_hash:
        raise RuntimeError("Rubika did not return an OTP request token.")
    print("📨 Verification code sent to your phone / Telegram / Rubika app.\n")

    # 4) Read the code from the user
    code = input("🔢 Enter the code you received: ").strip()
    if not code:
        raise ValueError("Verification code is required.")

    # 5) Create the key pair Rubika expects
    public_key, private_key = Crypto.create_keys()
    # Store the private key on the client object – needed right after sign‑in
    client.private_key = private_key

    # 6) Sign in (keyword arguments exactly as in the proven auth helper)
    sign_in_result = await client.sign_in(
        phone_code=code,
        phone_number=phone,
        phone_code_hash=phone_code_hash,
        public_key=public_key,
    )

    # 7) Post‑sign‑in session setup (copied directly from the working helper)
    sign_in_result.auth = Crypto.decrypt_RSA_OAEP(client.private_key, sign_in_result.auth)
    client.key = Crypto.passphrase(sign_in_result.auth)
    client.auth = sign_in_result.auth
    client.decode_auth = Crypto.decode_auth(client.auth)
    client.import_key = (
        pkcs1_15.new(RSA.import_key(client.private_key.encode()))
        if client.private_key is not None
        else None
    )
    client.session.insert(
        phone_number=sign_in_result.user.phone,
        auth=client.auth,
        guid=sign_in_result.user.user_guid,
        user_agent=client.user_agent,
        private_key=client.private_key,
    )
    await client.register_device(device_model=client.name)

    print("✅ Login successful! Session saved.\n")
    return client


# ----------------------------------------------------------------------
# Progress callback (simple text‑based bar)
# ----------------------------------------------------------------------
def progress_callback(current: int, total: int):
    """Simple text‑based progress bar."""
    if total == 0:
        return
    percent = current / total * 100
    bar_length = 40
    filled = int(bar_length * current // total)
    bar = '█' * filled + '-' * (bar_length - filled)
    print(f"\r📤 Uploading: |{bar}| {percent:.1f}% ", end='', flush=True)
    if current == total:
        print()


# ----------------------------------------------------------------------
# Main interactive loop
# ----------------------------------------------------------------------
async def main():
    print("\n" + "=" * 50)
    print("🚀 Rubika File Uploader – Send to Saved Messages")
    print("=" * 50)

    try:
        client = await get_client()
    except Exception as e:
        print(f"❌ Cannot initialise client: {e}")
        sys.exit(1)

    try:
        # Get your own GUID (Saved Messages)
        me = await client.get_me()
        my_guid = me.user.user_guid
        name_parts = f"{me.user.first_name or ''} {me.user.last_name or ''}".strip()
        print(f"👤 Logged in as: {name_parts}")
        print(f"📌 Your Saved Messages GUID: {my_guid}\n")

        while True:
            print("-" * 50)
            path = input("📁 Drag & drop a file path here (or type 'exit' to quit):\n> ").strip().strip('"').strip("'")
            if path.lower() in ('exit', 'quit', 'q'):
                print("👋 Goodbye!")
                break
            if not path:
                print("⚠️  No file path entered. Try again.\n")
                continue
            if not os.path.isfile(path):
                print(f"❌ File not found: {path}\n")
                continue

            file_name = os.path.basename(path)
            file_size = os.path.getsize(path)
            print(f"📄 File: {file_name} ({file_size / (1024*1024):.2f} MB)")

            try:
                print("⏳ Starting upload...")
                await client.send_message(
                    object_guid=my_guid,
                    file=path,
                    message=None,
                    progress=progress_callback,
                )
                print(f"✅ Successfully uploaded '{file_name}' to Saved Messages!\n")
            except Exception as e:
                print(f"\n❌ Upload error: {e}\n")

    finally:
        await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted. Bye!")
        sys.exit(0)