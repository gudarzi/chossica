#!/usr/bin/env python3
"""
Interactive Rubika File Uploader
Uploads any file to your Rubika "Saved Messages" with a progress bar.
"""

import asyncio
import os
import sys
from rubpy import Client


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

    # The client must be connected before any API calls
    await client.connect()

    if await is_authorized(client):
        return client

    # ---------- Interactive login ----------
    print("\n🔐 No valid session found. Let's log in to Rubika.\n")
    phone = input("📱 Enter your phone number (international format, e.g. +98912...): ").strip()
    if not phone:
        raise ValueError("Phone number is required.")

    # Send verification code
    send_result = await client.send_code(phone)
    print("📨 Verification code sent to your phone / Telegram / Rubika app.\n")

    code = input("🔢 Enter the code you received: ").strip()
    if not code:
        raise ValueError("Verification code is required.")

    # Check for two‑step verification (if the result contains a password hint)
    password = None
    if hasattr(send_result, 'password') and send_result.password:
        password = input("🔑 Two‑step verification is enabled. Enter your password: ").strip()
        if not password:
            raise ValueError("Password is required for two‑step verification.")

    try:
        if password:
            await client.sign_in(phone, code, password=password)
        else:
            await client.sign_in(phone, code)
        print("✅ Login successful! Session saved.\n")
    except Exception as e:
        print(f"\n❌ Login failed: {e}")
        sys.exit(1)

    return client


# ----------------------------------------------------------------------
# Progress callback
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
        print()   # move to next line when complete


# ----------------------------------------------------------------------
# Main interactive loop
# ----------------------------------------------------------------------
async def main():
    print("\n" + "=" * 50)
    print("🚀 Rubika File Uploader - Send to Saved Messages")
    print("=" * 50)

    try:
        client = await get_client()
    except Exception as e:
        print(f"❌ Cannot initialise client: {e}")
        sys.exit(1)

    # Get your own GUID (Saved Messages)
    me = await client.get_me()
    my_guid = me.user.user_guid
    print(f"👤 Logged in as: {me.user.first_name or ''} {me.user.last_name or ''}".strip())
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
                message=None,           # no caption
                progress=progress_callback,
            )
            print(f"✅ Successfully uploaded '{file_name}' to Saved Messages!\n")
        except Exception as e:
            print(f"\n❌ Upload error: {e}\n")

    await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted. Bye!")
        sys.exit(0)