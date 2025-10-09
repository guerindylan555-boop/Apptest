#!/usr/bin/env python3
import sys
inbuf = sys.stdin.buffer
out = sys.stdout.buffer

buf = bytearray()
while True:
    chunk = inbuf.read(4096)
    if not chunk:
        break
    buf += chunk
    idx = buf.find(b'ftyp')
    if idx != -1:
        # include 4 bytes before 'ftyp' if present (box size)
        start = idx-4 if idx >= 4 else idx
        out.write(buf[start:])
        out.flush()
        # now stream rest directly
        while True:
            chunk = inbuf.read(8192)
            if not chunk:
                break
            out.write(chunk)
            out.flush()
        break