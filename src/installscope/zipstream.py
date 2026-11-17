"""Bounded stored/deflate decoding before any declared-length clipping.

ZipExtFile intentionally truncates returned output to the declared file_size.
That is not sufficient for an auditor counting actual decompressed bytes.
"""
import struct
import zlib

LOCAL = bytes([80, 75, 3, 4])
DESCRIPTOR = bytes([80, 75, 7, 8])


def iter_member(raw, info, boundary, budget):
    """Yield validated output chunks; exhaust the iterator to finish CRC checks."""
    if budget < 0 or info.file_size > budget:
        raise ValueError('expanded byte budget exceeded')
    raw.seek(info.header_offset)
    header = raw.read(30)
    if len(header) != 30:
        raise ValueError('truncated local ZIP header')
    local = struct.unpack('<4s5H3L2H', header)
    if local[0] != LOCAL or local[2] != info.flag_bits or local[3] != info.compress_type:
        raise ValueError('local/central ZIP header disagreement')
    if info.flag_bits & ~0x80E or info.compress_type not in (0, 8):
        raise ValueError('unsupported ZIP flags, encryption or compression')
    if local[7] == 4294967295 or local[8] == 4294967295:
        raise ValueError('ZIP64 local size fields are unsupported')
    name_size, extra_size = local[9:11]
    start = info.header_offset + 30 + name_size + extra_size
    if not 1 <= name_size <= 4096 or start + info.compress_size > boundary:
        raise ValueError('local member extent overlaps another ZIP record')
    encoded_name = raw.read(name_size)
    encoding = 'utf-8' if info.flag_bits & 0x800 else 'cp437'
    if encoded_name.decode(encoding) != info.orig_filename:
        raise ValueError('local/central member names disagree')
    if len(raw.read(extra_size)) != extra_size:
        raise ValueError('truncated local ZIP extra field')
    if not info.flag_bits & 8 and local[6:9] != (info.CRC, info.compress_size, info.file_size):
        raise ValueError('local/central member sizes or CRC disagree')
    if info.compress_type == 0 and info.compress_size != info.file_size:
        raise ValueError('stored member lengths disagree')

    actual, crc = 0, 0
    decoder = zlib.decompressobj(-15) if info.compress_type == 8 else None

    def accept(block):
        nonlocal actual, crc
        actual += len(block)
        if actual > budget or actual > info.file_size:
            raise ValueError('actual decompressed output exceeds budget or declared length')
        crc = zlib.crc32(block, crc)
        return block

    def capacity():
        # One sentinel byte is enough to detect excess output without materializing it.
        return min(65536, budget - actual + 1, info.file_size - actual + 1)

    compressed_left = info.compress_size
    while compressed_left:
        data = raw.read(min(65536, compressed_left))
        if not data:
            raise ValueError('truncated compressed member')
        compressed_left -= len(data)
        if decoder is None:
            yield accept(data)
            continue
        pending = data
        while pending:
            previous = pending
            block = decoder.decompress(pending, capacity())
            pending = decoder.unconsumed_tail
            if decoder.unused_data or (decoder.eof and (pending or compressed_left)):
                raise ValueError('extra bytes after deflate stream')
            if block:
                yield accept(block)
            if pending == previous and not block:
                raise ValueError('deflate decoder made no progress')
    if decoder is not None:
        while not decoder.eof:
            block = decoder.decompress(b'', capacity())
            if not block:
                break
            yield accept(block)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('deflate stream did not end at its declared boundary')
    if actual != info.file_size or crc != info.CRC:
        raise ValueError('actual member length or CRC mismatch')
    if info.flag_bits & 8:
        position = start + info.compress_size
        raw.seek(position)
        first = raw.read(4)
        if first == DESCRIPTOR:
            descriptor = raw.read(12)
            end = position + 16
        else:
            descriptor = first + raw.read(8)
            end = position + 12
        if len(descriptor) != 12 or end > boundary:
            raise ValueError('truncated/overlapping data descriptor')
        if struct.unpack('<3L', descriptor) != (info.CRC, info.compress_size, info.file_size):
            raise ValueError('data descriptor disagrees with validated member')
