#!/usr/bin/env python3
"""
Interactive Rubika File Uploader
Uploads any file to your Rubika "Saved Messages" with a progress bar.
Reuses an existing session when possible.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import zipfile
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from rubpy import Client
from rubpy.crypto import Crypto


# ─────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("rubika_uploader")

if LOG_LEVEL != "DEBUG":
    for _noisy in ("rubpy", "aiohttp", "asyncio"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)


# ─────────────────────────────────────────────
# Optional zip password argument
# ─────────────────────────────────────────────
PASSWORD_ARG = None
if len(sys.argv) > 1:
    PASSWORD_ARG = sys.argv[1]
    log.debug("Zip password argument provided.")


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
SESSION_NAME     = "rubika.session"
PRIVATE_KEY_FILE = Path(f"{SESSION_NAME}.key")   # our own sidecar – rubpy never touches this

MAX_RETRIES = 5
RETRY_DELAY = 3


# ─────────────────────────────────────────────
# Phone normalisation
# ─────────────────────────────────────────────
def normalize_phone(phone: str) -> str:
    phone = phone.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    match = re.match(r"^(?:\+|00)?(\d{7,15})$", phone)
    if not match:
        raise ValueError(f"Invalid phone number: {phone!r}")
    n = match.group(1)
    if n.startswith("0"):
        n = f"98{n[1:]}"
    elif n.startswith("9") and len(n) == 10:
        n = f"98{n}"
    return n


# ─────────────────────────────────────────────
# Private-key sidecar helpers
# ─────────────────────────────────────────────
def save_private_key(private_key: str) -> None:
    """Persist the RSA private key to our own sidecar file."""
    PRIVATE_KEY_FILE.write_text(private_key, encoding="utf-8")
    log.debug("Private key saved to %s", PRIVATE_KEY_FILE)


def load_private_key() -> str | None:
    """Read the RSA private key from our sidecar file."""
    if not PRIVATE_KEY_FILE.exists():
        log.debug("No private key sidecar found at %s", PRIVATE_KEY_FILE)
        return None
    key = PRIVATE_KEY_FILE.read_text(encoding="utf-8").strip()
    if not key:
        log.debug("Private key sidecar is empty.")
        return None
    log.debug("Private key loaded from %s", PRIVATE_KEY_FILE)
    return key


# ─────────────────────────────────────────────
# Session file helpers
# ─────────────────────────────────────────────
_SESSION_EXTENSIONS = ("", ".rp", ".session", ".sqlite")


def session_file_exists() -> bool:
    return any(Path(f"{SESSION_NAME}{ext}").exists() for ext in _SESSION_EXTENSIONS)


# ─────────────────────────────────────────────
# Session management
# ─────────────────────────────────────────────
async def try_reuse_session() -> Client | None:
    """
    Try to reconnect using the saved session + our private-key sidecar.

    rubpy's connect() reloads auth/guid from the .rp file fine, but it never
    restores client.private_key, so client.import_key stays None and every
    signed API call fails. We fix that by reading the private key from our
    own sidecar file (written at login time) and wiring it in ourselves.
    rubpy's session file is left completely untouched.
    """
    if not session_file_exists():
        log.info("No rubpy session file found – fresh login needed.")
        return None

    pk = load_private_key()
    if not pk:
        log.warning(
            "Session file exists but private key sidecar (%s) is missing. "
            "A fresh login is required to recreate it.",
            PRIVATE_KEY_FILE,
        )
        return None

    log.info("Session + private key found – attempting to reuse...")
    client = Client(name=SESSION_NAME)
    try:
        await client.connect()
        log.debug("connect() succeeded.")

        # Wire everything that connect() silently skips.
        # - private_key / import_key: needed to sign outgoing requests.
        # - decode_auth: needed to decrypt incoming responses.
        #   Without it rubpy decrypts garbage and KeyError: 'status' is raised.
        client.private_key  = pk
        client.import_key   = pkcs1_15.new(RSA.import_key(pk.encode()))
        if getattr(client, "auth", None) and not getattr(client, "decode_auth", None):
            client.decode_auth = Crypto.decode_auth(client.auth)
        log.debug("import_key and decode_auth wired from saved data.")

        # Validate with a lightweight API call.
        await client.get_me()
        log.info("Existing session is valid ✓")
        return client

    except Exception as exc:
        log.warning(
            "Session reuse failed (%s: %s) – will do a fresh login.",
            type(exc).__name__,
            exc,
        )
        try:
            await client.disconnect()
        except Exception:
            pass
        return None


async def fresh_login() -> Client:
    """
    Interactive OTP login. Returns a fully authenticated Client
    with rubpy's session file and our private-key sidecar both saved to disk.
    """
    print("\n🔐 No valid session found. Let's log in to Rubika.\n")

    raw_phone = input("📱 Enter your phone number (e.g. +98912...): ").strip()
    if not raw_phone:
        raise ValueError("Phone number is required.")
    phone = normalize_phone(raw_phone)
    log.debug("Normalised phone: %s", phone)

    client = Client(name=SESSION_NAME)
    await client.connect()

    try:
        # 1. Request OTP
        send_result = await client.send_code(phone_number=phone, send_type="SMS")

        if getattr(send_result, "status", "") == "SendPassKey":
            hint = getattr(send_result, "hint_pass_key", "") or ""
            print(f"\n🔑 Two-step verification is enabled.{f'  Hint: {hint}' if hint else ''}")
            pass_key = input("Password: ").strip()
            if not pass_key:
                raise ValueError("Password is required.")
            send_result = await client.send_code(phone_number=phone, pass_key=pass_key)

        status = getattr(send_result, "status", "")
        if status != "OK":
            raise RuntimeError(
                f"OTP request failed (status={status!r}). "
                "Double-check your phone number and try again."
            )

        phone_code_hash = getattr(send_result, "phone_code_hash", None)
        if not phone_code_hash:
            raise RuntimeError("Rubika did not return an OTP token.")

        print("📨 Verification code sent to your phone / Rubika / Telegram app.\n")

        # 2. Collect code & generate RSA keypair
        code = input("🔢 Enter the verification code: ").strip()
        if not code:
            raise ValueError("Verification code is required.")

        public_key, private_key = Crypto.create_keys()
        client.private_key = private_key

        # 3. Sign in
        sign_in_result = await client.sign_in(
            phone_code=code,
            phone_number=phone,
            phone_code_hash=phone_code_hash,
            public_key=public_key,
        )

        sign_in_status = getattr(sign_in_result, "status", "")
        if sign_in_status != "OK":
            raise RuntimeError(
                f"Sign-in failed (status={sign_in_status!r}). "
                "The code may be wrong or expired."
            )

        # 4. Finalise crypto state
        sign_in_result.auth = Crypto.decrypt_RSA_OAEP(client.private_key, sign_in_result.auth)
        client.key         = Crypto.passphrase(sign_in_result.auth)
        client.auth        = sign_in_result.auth
        client.decode_auth = Crypto.decode_auth(client.auth)
        client.import_key  = pkcs1_15.new(RSA.import_key(client.private_key.encode()))

        # 5. Let rubpy save its session file normally (don't interfere).
        client.session.insert(
            phone_number=sign_in_result.user.phone,
            auth=client.auth,
            guid=sign_in_result.user.user_guid,
            user_agent=client.user_agent,
            private_key=client.private_key,
        )
        await client.register_device(device_model=client.name)

        # 6. Save our own private-key sidecar so future runs can restore import_key.
        save_private_key(client.private_key)

        if not session_file_exists():
            raise RuntimeError(
                "Login appeared to succeed but no session file was created. "
                "Check write permissions in the current directory."
            )

        log.info("Login successful – session and key sidecar saved.")
        print("✅ Login successful! Session saved.\n")
        return client

    except Exception:
        try:
            await client.disconnect()
        except Exception:
            pass
        raise


# ─────────────────────────────────────────────
# Upload helpers
# ─────────────────────────────────────────────
def build_file_inline(uploaded: dict) -> dict:
    """
    Normalize Rubika file payload while preserving
    Rubika-required upload metadata.
    """

    payload = dict(uploaded)

    # ONLY force generic file type
    payload["type"] = "File"

    # Remove invalid None keys only
    cleaned = {}

    for k, v in payload.items():
        if k is None:
            continue

        if v is None:
            continue

        cleaned[str(k)] = v

    return cleaned

async def upload_progress_callback(total: int, current: int) -> None:
    if total == 0:
        return
    percent    = current / total * 100
    bar_length = 40
    filled     = int(bar_length * current // total)
    bar        = "█" * filled + "-" * (bar_length - filled)
    print(f"\r📤 Uploading: |{bar}| {percent:.1f}% ", end="", flush=True)
    if current >= total:
        print()


# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────
async def main() -> None:
    print("\n" + "=" * 52)
    print("  🚀  Rubika File Uploader – Send to Saved Messages")
    print("=" * 52)

    client = await try_reuse_session()
    if client is None:
        # ── Attempt to restore session from encrypted zip ──────────────
        zip_path = Path(__file__).resolve().parent / "my_session.zip"
        if zip_path.is_file():
            if PASSWORD_ARG is not None:
                print("🔐 Encrypted session zip found. Attempting to extract...")
                try:
                    with zipfile.ZipFile(zip_path) as zf:
                        zf.extractall(path=Path(__file__).resolve().parent,
                                      pwd=PASSWORD_ARG.encode())
                    print("✅ Session files extracted. Trying to reuse...")
                    client = await try_reuse_session()
                except Exception as exc:
                    log.warning("Zip extraction failed: %s", exc)
                    print(f"❌ Failed to extract zip: {exc}. Will proceed to fresh login.")
            else:
                print("ℹ️ Encrypted session zip found but no password argument provided. "
                      "Skipping extraction.")

        # If still no client, launch interactive login
        if client is None:
            try:
                client = await fresh_login()
            except Exception as exc:
                log.error("Login failed: %s", exc)
                sys.exit(1)

    try:
        me      = await client.get_me()
        my_guid = me.user.user_guid
        name    = f"{me.user.first_name or ''} {me.user.last_name or ''}".strip()
        print(f"👤 Logged in as : {name}")
        print(f"📌 Saved Messages GUID: {my_guid}\n")

        while True:
            print("-" * 52)
            path_str = (
                input("📁 Drop a file path here (or 'exit' to quit):\n> ")
                .strip()
                .strip('"')
                .strip("'")
            )
            if path_str.lower() in ("exit", "quit", "q"):
                print("👋 Goodbye!")
                break
            if not path_str:
                print("⚠️  No path entered. Try again.\n")
                continue
            if not os.path.isfile(path_str):
                print(f"❌ File not found: {path_str}\n")
                continue

            file_name = os.path.basename(path_str)
            file_size = os.path.getsize(path_str)
            print(f"📄 {file_name}  ({file_size / (1024 * 1024):.2f} MB)")

            try:
                print("⏳ Starting upload...")
                uploaded = await client.upload(
                    path_str,
                    callback=upload_progress_callback,
                    file_name=file_name,
                )

                file_inline = (
                    dict(uploaded)
                    if isinstance(uploaded, dict)
                    else uploaded.to_dict
                )

                file_inline = build_file_inline(file_inline)

                last_error = None

                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        await client.send_message(
                            object_guid=my_guid,
                            file_inline=file_inline,
                            text="aaaa",
                        )
                        break

                    except Exception as exc:
                        last_error = exc

                        log.warning(
                            "Finalize attempt %s/%s failed: %s",
                            attempt,
                            MAX_RETRIES,
                            exc,
                        )

                        if attempt >= MAX_RETRIES:
                            raise

                        await asyncio.sleep(RETRY_DELAY * attempt)

                print(f"✅ '{file_name}' sent to Saved Messages!\n")

            except Exception as exc:
                log.error("Upload error (%s): %s", type(exc).__name__, exc)
                print(f"\n❌ Upload error: {exc}\n")

    finally:
        try:
            await client.disconnect()
            log.debug("Client disconnected cleanly.")
        except Exception as exc:
            log.debug("Disconnect error (ignored): %s", exc)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted. Bye!")
        sys.exit(0)