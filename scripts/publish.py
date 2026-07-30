#!/usr/bin/env python3
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "rules" / "rules.json"
REVISION_FILE = ROOT / "revision.txt"
CERTIFICATE_FILE = ROOT / "certs" / "rules-signing.pem"
PAYLOAD_FILE = ROOT / "payload.json"
ENVELOPE_FILE = ROOT / "stable.json"


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def write_atomic(path: Path, content: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    os.replace(temporary, path)


def main() -> None:
    key_value = os.environ.get("RULE_SIGNING_KEY_FILE")
    if not key_value:
        raise SystemExit("RULE_SIGNING_KEY_FILE is required")
    key_file = Path(key_value)

    revision_text = REVISION_FILE.read_text(encoding="utf-8").strip()
    if not revision_text.isdigit():
        raise SystemExit("revision.txt must contain an unsigned integer")
    revision = int(revision_text) + 1

    rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    if not isinstance(rules, list) or len(rules) > 64:
        raise SystemExit("rules.json must be an array containing at most 64 rules")

    issued_at = int(time.time())
    payload = {
        "schema_version": 1,
        "revision": revision,
        "issued_at": issued_at,
        "expires_at": issued_at + 90 * 24 * 60 * 60,
        "rules": rules,
    }
    payload_bytes = (
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")

    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        payload_path = work / "payload.json"
        signature_path = work / "payload.sig"
        key_public = work / "key-public.pem"
        certificate_public = work / "certificate-public.pem"
        payload_path.write_bytes(payload_bytes)

        with key_public.open("wb") as output:
            subprocess.run(
                ["openssl", "pkey", "-in", str(key_file), "-pubout"],
                check=True,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
        with certificate_public.open("wb") as output:
            subprocess.run(
                ["openssl", "x509", "-in", str(CERTIFICATE_FILE), "-pubkey", "-noout"],
                check=True,
                stdout=output,
            )
        if key_public.read_bytes() != certificate_public.read_bytes():
            raise SystemExit("signing key does not match the published certificate")

        run(
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(key_file),
            "-out",
            str(signature_path),
            str(payload_path),
        )
        run(
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(key_public),
            "-signature",
            str(signature_path),
            str(payload_path),
        )

        envelope = {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signature": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
        }
        envelope_bytes = (
            json.dumps(envelope, ensure_ascii=True, indent=2) + "\n"
        ).encode("utf-8")

    write_atomic(PAYLOAD_FILE, payload_bytes)
    write_atomic(ENVELOPE_FILE, envelope_bytes)
    write_atomic(REVISION_FILE, f"{revision}\n".encode("ascii"))
    print(f"Published client fingerprint rule revision {revision}")


if __name__ == "__main__":
    main()
