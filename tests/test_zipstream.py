"""Owner-run raw decoder controls, independent of the wheel fixture builder."""
import io
import random
import struct
import unittest
import zipfile
import zlib

from installscope.zipstream import iter_member


def record(payload, method=8, *, descriptor=False, trailer=b'', truncate=False):
    if method == 8:
        compressor = zlib.compressobj(wbits=-15)
        encoded = compressor.compress(payload) + compressor.flush()
    else:
        encoded = payload
    if truncate:
        encoded = encoded[:-1]
    encoded += trailer
    info = zipfile.ZipInfo('payload.bin')
    info.header_offset = 0
    info.flag_bits = 8 if descriptor else 0
    info.compress_type = method
    info.file_size = len(payload)
    info.compress_size = len(encoded)
    info.CRC = zlib.crc32(payload)
    sizes = (0, 0, 0) if descriptor else (info.CRC, info.compress_size, info.file_size)
    name = info.filename.encode()
    header = struct.pack('<4s5H3L2H', bytes([80, 75, 3, 4]), 20, info.flag_bits, method, 0, 0,
                         *sizes, len(name), 0)
    data = header + name + encoded
    if descriptor:
        data += bytes([80, 75, 7, 8]) + struct.pack('<3L', info.CRC, info.compress_size, info.file_size)
    return bytearray(data), info


class RawDecoderTests(unittest.TestCase):
    def test_chunk_boundaries_roundtrip_against_original_bytes(self):
        rng = random.Random(712)
        for size in (0, 1, 2, 100, 65535, 65536, 65537, 131072):
            for compressible in (False, True):
                payload = b'x' * size if compressible else rng.randbytes(size)
                for method in (0, 8):
                    for descriptor in (False, True):
                        with self.subTest(size=size, compressible=compressible, method=method, descriptor=descriptor):
                            data, info = record(payload, method, descriptor=descriptor)
                            blocks = list(iter_member(io.BytesIO(data), info, len(data), len(payload)))
                            self.assertEqual(b''.join(blocks), payload)
                            self.assertTrue(all(len(block) <= 65536 for block in blocks))

    def test_deflate_trailing_data_rejected(self):
        data, info = record(b'original data', trailer=b'not part of deflate')
        with self.assertRaisesRegex(ValueError, 'extra bytes'):
            list(iter_member(io.BytesIO(data), info, len(data), 100))

    def test_truncated_stream_rejected(self):
        data, info = record(b'original data', truncate=True)
        with self.assertRaisesRegex(ValueError, 'did not end'):
            list(iter_member(io.BytesIO(data), info, len(data), 100))

    def test_wrong_descriptor_rejected(self):
        data, info = record(b'original data', descriptor=True)
        data[-12] ^= 1
        with self.assertRaisesRegex(ValueError, 'descriptor disagrees'):
            list(iter_member(io.BytesIO(data), info, len(data), 100))

    def test_output_budget_refusal(self):
        data, info = record(b'x' * 100000)
        with self.assertRaisesRegex(ValueError, 'budget'):
            list(iter_member(io.BytesIO(data), info, len(data), 1000))


if __name__ == '__main__':
    unittest.main()
