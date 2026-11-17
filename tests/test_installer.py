"""Independent pip oracle, using only locally generated harmless packages."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_analysis import wheel


class InstallerOracle(unittest.TestCase):
    def test_root_and_purelib_map_to_same_real_relative_path(self):
        from installscope import audit_wheels
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = wheel(root, 'oracla', {'shared/config.py': b'value = 1\n'})
            b = wheel(root, 'oraclb', {'oraclb-1.0.data/purelib/shared/config.py': b'value = 2\n'})
            for index, path in enumerate((a, b), 1):
                target = root / ('target' + str(index))
                result = subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps',
                                         '--no-compile', '--disable-pip-version-check', '--target', str(target), str(path)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((target / 'shared/config.py').read_text().strip(), 'value = ' + str(index))
            report = audit_wheels([a, b])
            self.assertEqual(report['status'], 'CONFLICT')
            collision = next(f for f in report['findings'] if f['rule'] == 'file_collision')
            self.assertTrue(collision['destination'].endswith('/shared/config.py'))
            self.assertEqual({o['owner'] for o in collision['owners']}, {'oracla@1.0', 'oraclb@1.0'})


if __name__ == '__main__':
    unittest.main()
