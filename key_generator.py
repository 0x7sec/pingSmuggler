#!/usr/bin/env python3

import os, argparse


def generate_aes_key(size=16):
    key = os.urandom(size)
    return key


argparser = argparse.ArgumentParser(description="AES key generator")
argparser.add_argument(
    "-s", "--size", type=int, default=16, help="Key size in bytes (16, 24, or 32)"
)
args = argparser.parse_args()

if args.size not in [16, 24, 32]:
    print("Error: Invalid key size. Key must be 16, 24, or 32 bytes long for AES.")
    print("defaulting to 16 bytes")
    args.size = 16

key = generate_aes_key(args.size)
print(f"Generated {args.size}-byte AES key: {key.hex()}")
