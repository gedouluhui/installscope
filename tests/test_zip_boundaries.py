"""Adversarial local archives reproducing independent review findings."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from installscope import audit_wheels
from test_analysis import wheel

EOCD = bytes([80, 75, 5, 6])
ZIP64_END = bytes([80, 75, 6, 6])
ZIP64_LOCATOR = bytes([80, 75, 6, 7])


def conceal_zip64_directory(path):
    original = path.read_bytes()
    at = original.rfind(EOCD)
    end = struct.unpack('<4s4H2LH', original[at:at + 22])
    count, size, offset = end[4], end[5], end[6]
    directory = original[offset:offset + size]
    cover = bytearray(directory[:46])
    name = b'cover'
    real_offset = offset + 46 + len(name)
    end64 = struct.pack('<4sQ2H2L4Q', ZIP64_END, 44, 45, 45, 0, 0, count, count, size, real_offset)
    locator = struct.pack('<4sLQL', ZIP64_LOCATOR, 0, real_offset + size, 1)
    extra = directory + end64 + locator
    struct.pack_into('<HHH', cover, 28, len(name), len(extra), 0)
    fake_directory = bytes(cover) + name + extra
    ordinary = struct.pack('<4s4H2LH', EOCD, 0, 0, 1, 1, len(fake_directory), offset, 0)
    path.write_bytes(original[:offset] + fake_directory + ordinary)


def forge_short_uncompressed_size(path, member):
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(member)
    data = bytearray(path.read_bytes())
    struct.pack_into('<L', data, info.header_offset + 14, zlib.crc32(b'x'))
    struct.pack_into('<L', data, info.header_offset + 22, 1)
    at = data.rfind(EOCD)
    end = struct.unpack('<4s4H2LH', data[at:at + 22])
    cursor = end[6]
    while cursor < end[6] + end[5]:
        entry = struct.unpack('<4s6H3L5H2L', data[cursor:cursor + 46])
        name = bytes(data[cursor + 46:cursor + 46 + entry[10]]).decode('utf-8')
        if name == member:
            struct.pack_into('<L', data, cursor + 16, zlib.crc32(b'x'))
            struct.pack_into('<L', data, cursor + 24, 1)
        cursor += 46 + sum(entry[10:13])
    path.write_bytes(data)


class ZipBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_hidden_zip64_cannot_override_preflight_directory(self):
        path = wheel(self.root, 'a', {'pkg.py': b'x=1'})
        conceal_zip64_directory(path)
        # Positive control: the standard parser sees the larger, hidden directory.
        with zipfile.ZipFile(path) as parser:
            self.assertGreater(len(parser.infolist()), 1)
        self.assertEqual(audit_wheels([path])['status'], 'ERROR')

    def test_hidden_zip64_refused_before_inventory_allocation(self):
        path = wheel(self.root, 'a', {'pkg.py': b'x=1'})
        conceal_zip64_directory(path)
        with patch('installscope.archive.zipfile.ZipFile', wraps=zipfile.ZipFile) as parser:
            result = audit_wheels([path], max_members=1)
            self.assertEqual(result['status'], 'ERROR')
            self.assertEqual(parser.call_count, 0)

    def test_deflate_size_forgery_cannot_hide_output(self):
        path = wheel(self.root, 'a', {'pkg.py': b'x' * 100000}, record_override={'pkg.py': b'x'})
        forge_short_uncompressed_size(path, 'pkg.py')
        # Establish the dangerous standard-library truncation, not just a broken ZIP.
        with zipfile.ZipFile(path) as parser:
            self.assertEqual(parser.read('pkg.py'), b'x')
        result = audit_wheels([path], max_uncompressed_bytes=1000)
        self.assertEqual(result['status'], 'ERROR')

    def test_valid_stored_and_streaming_descriptor_controls(self):
        import io

        class NonSeekable(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation('streaming fixture')

        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            for streaming in (False, True):
                with self.subTest(compression=compression, streaming=streaming):
                    path = wheel(self.root, 'a', {'pkg.py': b'x' * 100000})
                    with zipfile.ZipFile(path) as parser:
                        members = {i.filename: parser.read(i) for i in parser.infolist()}
                    target = NonSeekable() if streaming else io.BytesIO()
                    with zipfile.ZipFile(target, 'w', compression=compression) as output:
                        for name, content in members.items():
                            output.writestr(name, content)
                    path.write_bytes(target.getvalue())
                    self.assertEqual(audit_wheels([path])['status'], 'CLEAR')

    def test_payload_reader_does_not_use_clipping_zipextfile(self):
        path = wheel(self.root, 'a', {'pkg.py': b'x' * 100000})
        with patch('zipfile.ZipFile.open', side_effect=AssertionError('must decode before clipping')):
            self.assertEqual(audit_wheels([path])['status'], 'CLEAR')

    def test_raw_decoder_rejects_unsupported_encryption_and_patch_flags(self):
        for flag in (0x40, 0x20, 0x4000):
            with self.subTest(flag=flag):
                path = wheel(self.root, 'a', {'pkg.py': b'abc'})
                data = bytearray(path.read_bytes())
                at = data.rfind(EOCD)
                directory = struct.unpack('<4s4H2LH', data[at:at + 22])[6]
                struct.pack_into('<H', data, 6, flag)
                struct.pack_into('<H', data, directory + 8, flag)
                path.write_bytes(data)
                self.assertEqual(audit_wheels([path])['status'], 'ERROR')

    def test_crc_corruption_rejected_by_raw_decoder(self):
        path = wheel(self.root, 'a', {'pkg.py': b'abc'})
        data = bytearray(path.read_bytes())
        at = data.rfind(EOCD)
        directory = struct.unpack('<4s4H2LH', data[at:at + 22])[6]
        struct.pack_into('<L', data, 14, 0)
        struct.pack_into('<L', data, directory + 16, 0)
        path.write_bytes(data)
        result = audit_wheels([path])
        self.assertEqual(result['status'], 'ERROR')
        self.assertTrue(any('CRC' in f['detail'] for f in result['findings']))

    def test_ambiguous_windows_scheme_root_rejected(self):
        a = wheel(self.root, 'a', {'pkg.py': b'a'}, pure=True)
        b = wheel(self.root, 'b', {'pkg.py': b'b'}, pure=False)
        scheme = dict(purelib='C:/venv/site', platlib='C:/venv/site.', scripts='C:/venv/bin',
                      headers='C:/venv/include', data='C:/venv')
        self.assertEqual(audit_wheels([a, b], platform='windows', scheme=scheme)['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
