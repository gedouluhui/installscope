import argparse
import json
from pathlib import Path
import sys

from .analysis import audit_wheels
from .examples import demo
from .report import atomic_write, to_html, validate_outputs


class StructuredParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def unique_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError('duplicate scheme key')
        data[key] = value
    return data


def main(argv=None):
    p = StructuredParser(description='Analyze wheel payload destination conflicts without installing packages.')
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('audit')
    a.add_argument('wheels', nargs='+')
    a.add_argument('--platform', choices=['posix', 'windows'], default='posix')
    a.add_argument('--scheme')
    a.add_argument('--json')
    a.add_argument('--html')
    for key, default in [('archive-bytes', 268435456), ('uncompressed-bytes', 536870912), ('members', 20000), ('metadata-bytes', 2097152)]:
        a.add_argument('--max-' + key, type=int, default=default)
    sub.add_parser('demo').add_argument('--output', required=True)
    try:
        args = p.parse_args(argv)
        if args.command == 'demo':
            statuses = demo(args.output)
            print(json.dumps(statuses))
            return 0 if statuses == {'clear': 'CLEAR', 'collision': 'CONFLICT'} else 2
        inputs = args.wheels + ([args.scheme] if args.scheme else [])
        validate_outputs([args.json, args.html], inputs)
        scheme = None
        if args.scheme:
            with Path(args.scheme).open('rb') as stream:
                raw = stream.read(2097153)
            if len(raw) > 2097152:
                raise ValueError('scheme JSON size limit exceeded')
            scheme = json.loads(raw, object_pairs_hook=unique_object)
        report = audit_wheels(args.wheels, platform=args.platform, scheme=scheme,
                              max_archive_bytes=args.max_archive_bytes, max_uncompressed_bytes=args.max_uncompressed_bytes,
                              max_members=args.max_members, max_metadata_bytes=args.max_metadata_bytes)
        text = json.dumps(report, indent=2, allow_nan=False, ensure_ascii=True)
        if args.json:
            atomic_write(args.json, text + '\n')
        if args.html:
            atomic_write(args.html, to_html(report))
        print(text)
        return {'CLEAR': 0, 'CONFLICT': 1, 'ERROR': 2, 'INCOMPLETE': 3}[report['status']]
    except (ValueError, OSError) as exc:
        print(json.dumps({'status': 'ERROR', 'error': str(exc) if isinstance(exc, ValueError) else type(exc).__name__}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
