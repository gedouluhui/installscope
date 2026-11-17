"""Harmless, self-generated wheel examples; no external package code."""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import zipfile

from .analysis import audit_wheels
from .report import atomic_write, to_html


def make_wheel(root, name, payload):
    prefix = name + '-1.0.dist-info/'
    files = dict(payload)
    files[prefix + 'METADATA'] = ('Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n').encode()
    files[prefix + 'WHEEL'] = b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    record = io.StringIO(newline='')
    writer = csv.writer(record, lineterminator='\n')
    for path, value in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b'=').decode()
        writer.writerow([path, 'sha256=' + digest, len(value)])
    writer.writerow([prefix + 'RECORD', '', ''])
    files[prefix + 'RECORD'] = record.getvalue().encode()
    path = root / (name + '-1.0-py3-none-any.whl')
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for member, content in files.items():
            z.writestr(member, content)
    return path


def demo(output):
    root = Path(output)
    if root.exists():
        raise ValueError('demo output must be a new directory')
    root.mkdir()
    a = make_wheel(root, 'demo_a', {'shared/config.py': b'value = 1\n'})
    b = make_wheel(root, 'demo_b', {'demo_b-1.0.data/purelib/shared/config.py': b'value = 2\n'})
    c = make_wheel(root, 'demo_c', {'shared/other.py': b'value = 3\n'})
    statuses = {}
    for case, inputs in [('clear', [a, c]), ('collision', [a, b])]:
        report = audit_wheels(inputs)
        atomic_write(root / (case + '.json'), json.dumps(report, indent=2, allow_nan=False))
        atomic_write(root / (case + '.html'), to_html(report))
        statuses[case] = report['status']
    return statuses
