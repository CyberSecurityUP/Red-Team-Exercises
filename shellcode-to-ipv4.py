#!/usr/bin/env python3
"""
Red Team Exercises #61 - Shellcode to IPv4 Converter
Author: Joas Antonio dos Santos
Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises

Usage:
    msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin
    python3 shellcode_to_ipv4.py -i payload.bin
"""

import argparse
import sys
import os


def shellcode_to_ipv4(shellcode_bytes):
    """Convert raw shellcode bytes to IPv4 dotted-decimal strings (4 bytes each)."""
    ips = []
    padding = 4 - (len(shellcode_bytes) % 4)
    if padding != 4:
        shellcode_bytes += b'\x00' * padding

    for i in range(0, len(shellcode_bytes), 4):
        chunk = shellcode_bytes[i:i+4]
        ip = '.'.join(str(b) for b in chunk)
        ips.append(ip)

    return ips


def generate_cpp_array(ips):
    lines = ['const char* shellcode_ipv4[] = {']
    for i, ip in enumerate(ips):
        comma = ',' if i < len(ips) - 1 else ''
        lines.append(f'    "{ip}"{comma}')
    lines.append('};')
    lines.append(f'\nint num_ips = {len(ips)};')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Convert shellcode to IPv4 strings')
    parser.add_argument('-i', '--input', required=True, help='Input shellcode binary')
    parser.add_argument('-o', '--output', default=None, help='Output file')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, 'rb') as f:
        shellcode = f.read()

    print(f"[*] Read {len(shellcode)} bytes", file=sys.stderr)

    ips = shellcode_to_ipv4(shellcode)
    output = generate_cpp_array(ips)

    print(f"[+] Generated {len(ips)} IPv4 strings", file=sys.stderr)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
