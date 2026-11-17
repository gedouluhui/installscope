"""Verify the built wheel's contents and run its CLI outside the checkout."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command, cwd, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=120)
    require(result.returncode == 0, result.stdout + result.stderr)
    return result.stdout


def main():
    wheels = list((ROOT / 'dist').glob('installscope-*.whl'))
    require(len(wheels) == 1, 'build exactly one wheel in dist before checking it')
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        members = archive.namelist()
        require(len(set(members)) == len(members), 'duplicate wheel entries')
        require(all((m.startswith('installscope/') and m.endswith('.py')) or
                    (m.startswith('installscope-') and '.dist-info/' in m) for m in members),
                'wheel contains a non-allowlisted payload')
        require(not any('..' in m.split('/') or '__pycache__' in m or m.endswith(('.pyc', '.env')) for m in members),
                'wheel contains a forbidden path')
        for source in (ROOT / 'src/installscope').glob('*.py'):
            require(archive.read('installscope/' + source.name) == source.read_bytes(),
                    'packaged source differs from checkout: ' + source.name)
    with tempfile.TemporaryDirectory(prefix='installscope-wheel-') as directory:
        temp = Path(directory)
        target = temp / 'installed'
        run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps', '--disable-pip-version-check',
             '--target', str(target), str(wheel)], temp)
        env = os.environ.copy()
        env['PYTHONPATH'] = str(target)
        origin = run([sys.executable, '-c', 'import installscope; print(installscope.__file__)'], temp, env).strip()
        require(Path(origin).resolve().is_relative_to(target.resolve()), 'import did not originate in the installed wheel')
        output = temp / 'demo'
        run([sys.executable, '-m', 'installscope', 'demo', '--output', str(output)], temp, env)
        require(json.loads((output / 'clear.json').read_text())['status'] == 'CLEAR', 'installed normal demo failed')
        require(json.loads((output / 'collision.json').read_text())['status'] == 'CONFLICT', 'installed conflict demo failed')
    print(json.dumps({'distribution': wheel.name, 'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
                      'payload_allowlist': 'PASS', 'source_bytes': 'MATCH', 'isolated_installed_cli': 'PASS'}))


if __name__ == '__main__':
    main()
