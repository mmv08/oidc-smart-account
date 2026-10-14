#!/usr/bin/env python3
"""Sends one JSON request to the enclave over vsock and prints the response.

Run this script on the host (the parent EC2 instance). Examples:

  request.py --cid 16 '{"operation":"attest","challenge":"0x<32 random bytes>"}'
  request.py --cid 16 '{"operation":"sign","jwksUri":"https://www.googleapis.com/oauth2/v3/certs",
                        "chainId":1,"registry":"0x<key registry address>"}'
"""

import argparse
import json
import socket
import sys

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--cid", type=int, required=True, help="enclave CID from `nitro-cli run-enclave`")
parser.add_argument("--port", type=int, default=5000, help="vsock port of `tee-updater serve`")
parser.add_argument("request", help="JSON request")
args = parser.parse_args()

with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
    connection.settimeout(60)
    connection.connect((args.cid, args.port))
    connection.sendall(args.request.encode())
    connection.shutdown(socket.SHUT_WR)
    response = b""
    while chunk := connection.recv(65536):
        response += chunk

result = json.loads(response)
if "error" in result:
    parser.exit(1, result["error"] + "\n")
sys.stdout.write(response.decode() + "\n")
