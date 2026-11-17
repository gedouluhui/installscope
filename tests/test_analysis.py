import base64
import csv
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile


def wheel(root, name, payload, *, tamper=False, duplicate=False, symlink=False, pure=True, record_override=None):
    prefix = name + '-1.0.dist-info/'
    files = dict(payload)
    files[prefix + 'METADATA'] = ('Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n').encode()
    files[prefix + 'WHEEL'] = ('Wheel-Version: 1.0\nRoot-Is-Purelib: ' + str(pure).lower() + '\nTag: py3-none-any\n').encode()
    records = io.StringIO(newline='')
    writer = csv.writer(records, lineterminator='\n')
    for key, value in files.items():
        if not key.endswith('/'):
            declared = (record_override or {}).get(key, value)
            digest = base64.urlsafe_b64encode(hashlib.sha256(declared).digest()).rstrip(b'=').decode()
            writer.writerow([key, 'sha256=' + digest, len(declared)])
    writer.writerow([prefix + 'RECORD', '', ''])
    files[prefix + 'RECORD'] = records.getvalue().encode()
    if tamper:
        files[next(iter(payload))] += b'tampered'
    path = root / (name + '-1.0-py3-none-any.whl')
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for key, value in files.items():
            if symlink and key == next(iter(payload)):
                info = zipfile.ZipInfo(key)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, value)
            else:
                z.writestr(key, value)
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                z.writestr(next(iter(payload)), b'other')
    return path


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def audit(self, paths, **kwargs):
        self.assertIsNotNone(importlib.util.find_spec('installscope'), 'package must exist')
        import installscope
        self.assertTrue(callable(getattr(installscope, 'audit_wheels', None)), 'audit_wheels API must exist')
        return installscope.audit_wheels(paths, **kwargs)

    def rules(self, r):
        return {f['rule'] for f in r['findings']}

    def test_root_and_data_remap_collide(self):
        a = wheel(self.root, 'a', {'shared/config.py': b'x=1'})
        b = wheel(self.root, 'b', {'b-1.0.data/purelib/shared/config.py': b'x=2'})
        r = self.audit([a, b])
        self.assertEqual(r['status'], 'CONFLICT')
        self.assertIn('file_collision', self.rules(r))
        self.assertEqual(len(next(f for f in r['findings'] if f['rule'] == 'file_collision')['owners']), 2)

    def test_namespace_shared_directory_is_legal(self):
        a = wheel(self.root, 'a', {'namespace/a.py': b'a=1'})
        b = wheel(self.root, 'b', {'namespace/b.py': b'b=1'})
        r = self.audit([a, b])
        self.assertEqual(r['status'], 'CLEAR')
        self.assertFalse(r['scope']['existing_environment_checked'])
        self.assertIn('limits', r)
        self.assertEqual(r['limits']['max_members'], 20000)

    def test_equal_content_different_owners_is_conflict(self):
        a = wheel(self.root, 'a', {'same.py': b'x=1'})
        b = wheel(self.root, 'b', {'same.py': b'x=1'})
        r = self.audit([a, b])
        self.assertEqual(r['status'], 'CONFLICT')
        self.assertTrue(next(f for f in r['findings'] if f['rule'] == 'file_collision')['same_content'])

    def test_file_directory_prefix_conflict(self):
        a = wheel(self.root, 'a', {'pkg': b'file'})
        b = wheel(self.root, 'b', {'pkg/module.py': b'x=1'})
        self.assertIn('file_directory_collision', self.rules(self.audit([a, b])))

    def test_explicit_empty_directory_conflict(self):
        a = wheel(self.root, 'a', {'pkg': b'file'})
        b = wheel(self.root, 'b', {'pkg/': b''})
        self.assertIn('file_directory_collision', self.rules(self.audit([a, b])))

    def test_case_policy_is_not_host_policy(self):
        a = wheel(self.root, 'a', {'Pkg.py': b'a'})
        b = wheel(self.root, 'b', {'pkg.py': b'b'})
        self.assertEqual(self.audit([a, b], platform='posix')['status'], 'CLEAR')
        self.assertEqual(self.audit([a, b], platform='windows')['status'], 'CONFLICT')

    def test_distinct_purelib_platlib_schemes(self):
        a = wheel(self.root, 'a', {'pkg.py': b'a'}, pure=True)
        b = wheel(self.root, 'b', {'pkg.py': b'b'}, pure=False)
        scheme = {'purelib': '/env/pure', 'platlib': '/env/plat', 'scripts': '/env/bin',
                  'headers': '/env/include', 'data': '/env'}
        self.assertEqual(self.audit([a, b], scheme=scheme)['status'], 'CLEAR')

    def test_record_tamper(self):
        a = wheel(self.root, 'a', {'pkg.py': b'x=1'}, tamper=True)
        self.assertEqual(self.audit([a])['status'], 'ERROR')

    def test_duplicate_zip_name(self):
        a = wheel(self.root, 'a', {'pkg.py': b'x=1'}, duplicate=True)
        self.assertEqual(self.audit([a])['status'], 'ERROR')

    def test_unsafe_paths(self):
        for key in ('../outside.py', '/root.py', 'pkg/../outside.py', 'pkg\\outside.py'):
            with self.subTest(key=key):
                a = wheel(self.root, 'a', {key: b'x=1'})
                self.assertEqual(self.audit([a])['status'], 'ERROR')

    def test_symlinks_rejected(self):
        a = wheel(self.root, 'a', {'pkg.py': b'../other'}, symlink=True)
        self.assertEqual(self.audit([a])['status'], 'ERROR')

    def test_limits(self):
        a = wheel(self.root, 'a', {'pkg.py': b'x' * 2000})
        for kwargs in ({'max_uncompressed_bytes': 100}, {'max_archive_bytes': 1},
                       {'max_metadata_bytes': 10}, {'max_members': 2}, {'max_members': True}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.audit([a], **kwargs)['status'], 'ERROR')

    def test_no_inputs_and_corrupt_zip(self):
        self.assertEqual(self.audit([])['status'], 'ERROR')
        p = self.root / 'a-1.0-py3-none-any.whl'
        p.write_bytes(b'not a zip')
        self.assertEqual(self.audit([p])['status'], 'ERROR')

    def test_windows_reserved_path(self):
        for name in ('CON.py', 'file:stream', 'name. ', 'name.'):
            a = wheel(self.root, 'a', {name: b'x'})
            self.assertEqual(self.audit([a], platform='windows')['status'], 'ERROR')

    def test_pth_is_not_executed_and_is_not_automatically_malicious(self):
        marker = self.root / 'ran.txt'
        code = "import pathlib; pathlib.Path(" + repr(str(marker)) + ").write_text('ran')"
        a = wheel(self.root, 'a', {'startup.pth': code.encode()})
        self.assertFalse(marker.exists())
        r = self.audit([a])
        self.assertFalse(marker.exists(), 'inspecting wheel must not execute its startup code')
        self.assertEqual(r['status'], 'CLEAR')
        self.assertIn('pth_execution_line', self.rules(r))
        # Independent positive control: this exact harmless test payload can create its marker.
        exec(code, {})
        self.assertEqual(marker.read_text(), 'ran')

    def test_member_budget_checked_before_zipfile_allocates_inventory(self):
        from unittest.mock import patch
        a = wheel(self.root, 'a', {'pkg.py': b'x'})
        with patch('installscope.archive.zipfile.ZipFile', wraps=zipfile.ZipFile) as parser:
            self.assertEqual(self.audit([a], max_members=1)['status'], 'ERROR')
            self.assertEqual(parser.call_count, 0, 'central-directory limit must precede ZipFile inventory allocation')

    def test_false_central_directory_count_rejected(self):
        import struct
        a = wheel(self.root, 'a', {'pkg.py': b'x'})
        data = bytearray(a.read_bytes())
        end = data.rfind(bytes([80, 75, 5, 6]))
        self.assertGreater(end, 0)
        struct.pack_into('<HH', data, end + 8, 1, 1)
        a.write_bytes(data)
        self.assertEqual(self.audit([a])['status'], 'ERROR')

    def test_stop_after_bad_wheel_keeps_global_budget_bounded(self):
        a = wheel(self.root, 'a', {'a.py': b'bad'}, tamper=True)
        b = wheel(self.root, 'b', {'b.py': b'good'})
        r = self.audit([a, b])
        self.assertEqual(r['status'], 'ERROR')
        self.assertEqual(r['inputs'], [], 'do not reset failed-input budgets and continue reading more wheels')

    def test_duplicate_distribution_input(self):
        a = wheel(self.root, 'a', {'pkg.py': b'x'})
        self.assertEqual(self.audit([a, a])['status'], 'ERROR')

    def test_all_inputs_share_total_expansion_budget(self):
        a = wheel(self.root, 'a', {'a.py': b'x' * 1000})
        b = wheel(self.root, 'b', {'b.py': b'x' * 1000})
        one = self.audit([a])
        self.assertEqual(one['status'], 'CLEAR')
        budget = one['summary']['expanded_bytes'] + 500
        self.assertEqual(self.audit([a, b], max_uncompressed_bytes=budget)['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
