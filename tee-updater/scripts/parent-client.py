#!/usr/bin/env python3
"""Send one narrow JSON request to the measured Nitro enclave server."""

import argparse
import json
import os
import socket
import sys
from pathlib import Path

MAX_MESSAGE_BYTES = 64 * 1024
AWS_FIELDS = {
    "awsRegion": "AWS_REGION",
    "awsAccessKeyId": "AWS_ACCESS_KEY_ID",
    "awsSecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "awsSessionToken": "AWS_SESSION_TOKEN",
}


def read_bounded_file(path: str, max_bytes: int) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(max_bytes + 1)


def load_request(path: str) -> dict:
    raw = (
        sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
        if path == "-"
        else read_bounded_file(path, MAX_MESSAGE_BYTES)
    )
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("request exceeds 64 KiB")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    if "kmsCiphertextFile" in request:
        ciphertext_path = Path(request.pop("kmsCiphertextFile"))
        ciphertext = read_bounded_file(str(ciphertext_path), MAX_MESSAGE_BYTES)
        if len(ciphertext) > MAX_MESSAGE_BYTES:
            raise ValueError("KMS ciphertext exceeds 64 KiB")
        request["kmsCiphertext"] = ciphertext.decode("utf-8").strip()
    for field, variable in AWS_FIELDS.items():
        value = os.environ.get(variable)
        if not value:
            raise ValueError(f"missing {variable}")
        request[field] = value
    return request


def send_request(request: dict, cid: int, port: int) -> dict:
    encoded = json.dumps(request, separators=(",", ":")).encode()
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ValueError("encoded request exceeds 64 KiB")
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
        connection.settimeout(90)
        connection.connect((cid, port))
        connection.sendall(encoded)
        connection.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_MESSAGE_BYTES:
                raise ValueError("enclave response exceeds 64 KiB")
            chunks.append(chunk)
    response = json.loads(b"".join(chunks))
    if not isinstance(response, dict):
        raise ValueError("enclave response is not a JSON object")
    return response


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("request", help="JSON request file, or - for stdin")
    parser.add_argument("--cid", type=int, required=True, help="CID from nitro-cli run-enclave")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    response = send_request(load_request(args.request), args.cid, args.port)
    print(json.dumps(response, indent=2, sort_keys=True))
    if response.get("ok") is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
