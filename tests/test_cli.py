import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def call(self, *args):
        return subprocess.run([sys.executable, '-m', 'installscope', *map(str, args)],
                              capture_output=True, text=True)

    def test_real_demo_and_collision_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'demo'
            p = self.call('demo', '--output', out)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads((out / 'clear.json').read_text())['status'], 'CLEAR')
            r = json.loads((out / 'collision.json').read_text())
            self.assertEqual(r['status'], 'CONFLICT')
            self.assertTrue(any(f['rule'] == 'file_collision' for f in r['findings']))
            self.assertTrue((out / 'collision.html').is_file())
            a, b = out / 'demo_a-1.0-py3-none-any.whl', out / 'demo_b-1.0-py3-none-any.whl'
            p = self.call('audit', a, b)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertEqual(json.loads(p.stdout)['status'], 'CONFLICT')
            before = hashlib.sha256(a.read_bytes()).hexdigest()
            p = self.call('audit', a, '--json', a)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(hashlib.sha256(a.read_bytes()).hexdigest(), before)
            self.assertNotEqual(self.call('demo', '--output', out).returncode, 0)

    def test_bad_arguments_produce_structured_error(self):
        p = self.call('audit', 'absent.whl', '--max-members', 'bad')
        self.assertEqual(p.returncode, 2)
        self.assertTrue(p.stdout.strip(), 'invalid arguments must produce JSON')
        self.assertEqual(json.loads(p.stdout)['status'], 'ERROR')

    def test_ci_verifies_the_built_distribution(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / 'scripts/check_distribution.py').is_file(), 'built-wheel verifier must exist')
        workflow = (root / '.github/workflows/ci.yml').read_text()
        self.assertIn('python scripts/check_distribution.py', workflow)

    def test_html_does_not_execute_untrusted_names(self):
        self.assertIsNotNone(importlib.util.find_spec('installscope.report'), 'HTML renderer must exist')
        from installscope.report import to_html
        text = '</script><img src=x onerror=alert(1)>'
        result = {'status': 'ERROR', 'scope': {'meaning': text}, 'summary': {}, 'inventory': [],
                  'findings': [{'rule': text, 'detail': text, 'severity': 'error'}]}
        page = to_html(result)
        self.assertNotIn('<img', page)
        self.assertIn('&lt;img', page)
        self.assertNotIn('<script', page)


if __name__ == '__main__':
    unittest.main()
