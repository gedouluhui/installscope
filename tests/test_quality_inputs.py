"""Regression controls for explicit policies and descriptor interpretation."""
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib

from installscope import audit_wheels
from installscope.zipstream import iter_member
from test_analysis import wheel
from test_zipstream import record


class ExplicitPolicyTests(unittest.TestCase):
    def test_supplied_nonobject_schemes_are_not_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = wheel(root, 'a', {'pkg.py': b'a'})
            b = wheel(root, 'b', {'b-1.0.data/scripts/pkg.py': b'b'})
            for value in (None, [], 'default', False, 1):
                with self.subTest(value=value):
                    scheme = root / 'scheme.json'
                    scheme.write_text(json.dumps(value), encoding='utf-8')
                    p = subprocess.run([sys.executable, '-m', 'installscope', 'audit', str(a), str(b), '--scheme', str(scheme)],
                                       capture_output=True, text=True)
                    self.assertEqual(p.returncode, 2, p.stdout)
                    self.assertEqual(json.loads(p.stdout)['status'], 'ERROR')
            explicit = dict(purelib='/env/shared', platlib='/env/shared', scripts='/env/shared',
                            headers='/env/include', data='/env')
            self.assertEqual(audit_wheels([a, b], scheme=explicit)['status'], 'CONFLICT')
            self.assertEqual(audit_wheels([a, b])['status'], 'CLEAR')


class DescriptorTests(unittest.TestCase):
    def test_magic_crc_unsigned_and_signed_are_valid(self):
        payload = bytes.fromhex('ac0a7ad5')
        self.assertEqual(zlib.crc32(payload), 0x08074b50)
        data, info = record(payload, descriptor=True)
        for unsigned in (False, True):
            with self.subTest(unsigned=unsigned):
                raw = data[:-16] + data[-12:] if unsigned else data
                try:
                    result = b''.join(iter_member(io.BytesIO(raw), info, len(raw), len(payload)))
                except ValueError as exc:
                    self.fail('valid descriptor rejected: ' + str(exc))
                self.assertEqual(result, payload)

    def test_descriptor_reads_do_not_cross_record_boundary(self):
        payload = b'ordinary'
        data, info = record(payload, descriptor=True)
        unsigned = data[:-16] + data[-12:]
        end = len(unsigned)

        class BoundaryReader(io.BytesIO):
            def read(self, n=-1):
                if self.tell() >= end - 12:
                    if n < 0 or self.tell() + n > end:
                        raise AssertionError('descriptor read crossed into next record')
                return super().read(n)

        result = b''.join(iter_member(BoundaryReader(unsigned + b'next record'), info, end, len(payload)))
        self.assertEqual(result, payload)

    def test_full_wheel_with_magic_crc_unsigned_descriptor(self):
        class NonSeekable(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = wheel(root, 'a', {'payload.bin': bytes.fromhex('ac0a7ad5')})
            with zipfile.ZipFile(path) as z:
                members = {i.filename: z.read(i) for i in z.infolist()}
            buffer = NonSeekable()
            with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as z:
                for name, content in members.items():
                    z.writestr(name, content)
            data = bytearray(buffer.getvalue())
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                item = z.getinfo('payload.bin')
            header = struct.unpack('<4s5H3L2H', data[item.header_offset:item.header_offset + 30])
            descriptor = item.header_offset + 30 + header[9] + header[10] + item.compress_size
            self.assertEqual(bytes(data[descriptor:descriptor + 4]), bytes([80, 75, 7, 8]))
            del data[descriptor:descriptor + 4]
            end = data.rfind(bytes([80, 75, 5, 6]))
            old_offset = struct.unpack_from('<L', data, end + 16)[0]
            offset = old_offset - 4
            struct.pack_into('<L', data, end + 16, offset)
            cursor = offset
            while cursor < end:
                fields = struct.unpack('<4s6H3L5H2L', data[cursor:cursor + 46])
                if fields[16] > descriptor:
                    struct.pack_into('<L', data, cursor + 42, fields[16] - 4)
                cursor += 46 + sum(fields[10:13])
            path.write_bytes(data)
            with zipfile.ZipFile(path) as z:
                self.assertIsNone(z.testzip())
                self.assertEqual(z.read('payload.bin'), bytes.fromhex('ac0a7ad5'))
            report = audit_wheels([path])
            self.assertEqual(report['status'], 'CLEAR', report['findings'])


if __name__ == '__main__':
    unittest.main()
