"""Destination ownership, not arbitrary installer or malware simulation."""
from pathlib import Path

from .archive import inspect_wheel
from .scheme import Scheme


def audit_wheels(paths, *, platform='posix', scheme=None, max_archive_bytes=268435456,
                 max_uncompressed_bytes=536870912, max_members=20000, max_metadata_bytes=2097152):
    report = {'schema_version': 1, 'tool': 'installscope', 'version': '0.1.0', 'status': 'ERROR',
              'inputs': [], 'inventory': [], 'findings': [], 'scheme': {},
              'summary': {'expanded_bytes': 0, 'archive_bytes': 0, 'members': 0},
              'scope': {'existing_environment_checked': False, 'installer_generated_files_checked': False,
                        'inventory_complete': False,
                        'byte_accounting': 'Summary counts validated inventories; partial bytes from an aborted input are not included. Scanning stops on the first invalid input.',
                        'meaning': 'CLEAR covers only the declared wheel payload write set, not whole-environment safety.',
                        'windows_policy': 'conservative Unicode casefold with reserved-name rejection; not an exact Win32 filesystem emulator'}}
    try:
        for name, value in [('max_archive_bytes', max_archive_bytes), ('max_uncompressed_bytes', max_uncompressed_bytes),
                            ('max_members', max_members), ('max_metadata_bytes', max_metadata_bytes)]:
            if type(value) is not int or value <= 0:
                raise ValueError(name + ' must be a positive integer')
        report['limits'] = dict(max_archive_bytes=max_archive_bytes, max_uncompressed_bytes=max_uncompressed_bytes,
                                max_members=max_members, max_metadata_bytes=max_metadata_bytes)
        if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= 1024:
            raise ValueError('provide 1..1024 explicit wheel paths')
        mapper = Scheme(platform, scheme)
        report['scheme'] = {'platform': platform, 'roots': mapper.values}
        owners = set()
        destinations = {}
        for path in paths:
            try:
                w = inspect_wheel(path, max_archive_bytes=max_archive_bytes - report['summary']['archive_bytes'],
                                  max_uncompressed_bytes=max_uncompressed_bytes - report['summary']['expanded_bytes'],
                                  max_members=max_members - report['summary']['members'], max_metadata_bytes=max_metadata_bytes)
                if w['owner'] in owners:
                    raise ValueError('duplicate distribution/version input')
                owners.add(w['owner'])
                staged = []
                for item in w['inventory']:
                    destination = mapper.destination(w, item)
                    if destination is not None:
                        staged.append({**item, 'destination': destination, 'owner': w['owner']})
                # Commit an inventory only after the whole wheel maps successfully.
                for item in staged:
                    report['inventory'].append(item)
                    destinations.setdefault(item['destination'], []).append(item)
                report['inputs'].append({k: w[k] for k in ('input', 'owner', 'sha256')})
                for name in report['summary']:
                    report['summary'][name] += w[name]
                for item in w['startup']:
                    report['findings'].append({'rule': 'pth_execution_line', 'severity': 'info', 'owner': w['owner'],
                                               **item, 'detail': 'Import line observed in .pth; not executed. Whether site loads it depends on its installed location.'})
            except Exception as exc:
                report['findings'].append({'rule': 'invalid_wheel', 'severity': 'error', 'input': Path(path).name,
                                          'detail': str(exc) if type(exc) is ValueError else type(exc).__name__})
                # Do not spend the same remaining expansion budget again after
                # a partially read invalid input. Keep earlier confirmed evidence.
                break
        for destination, items in sorted(destinations.items()):
            files = [i for i in items if i['kind'] == 'file']
            dirs = [i for i in items if i['kind'] == 'directory']
            if len(files) > 1:
                report['findings'].append({'rule': 'file_collision', 'severity': 'conflict', 'destination': destination,
                                          'owners': files, 'same_content': len({i['sha256'] for i in files}) == 1,
                                          'detail': 'Multiple payload members own the same destination; identical bytes still have shared-uninstall risk.'})
            if files and dirs:
                report['findings'].append({'rule': 'file_directory_collision', 'severity': 'conflict',
                                          'destination': destination, 'owners': files + dirs,
                                          'detail': 'A destination is both an explicit directory and a file.'})
            parts = destination.split('/')
            for end in range(1, len(parts)):
                parent = '/'.join(parts[:end])
                ancestors = [i for i in destinations.get(parent, []) if i['kind'] == 'file']
                if ancestors:
                    report['findings'].append({'rule': 'file_directory_collision', 'severity': 'conflict',
                                              'destination': parent, 'owners': ancestors + items,
                                              'detail': 'A file destination is an ancestor directory required by another payload.'})
        severities = {f['severity'] for f in report['findings']}
        report['scope']['inventory_complete'] = 'error' not in severities
        report['status'] = 'ERROR' if 'error' in severities else 'CONFLICT' if 'conflict' in severities else 'CLEAR'
    except Exception as exc:
        report['findings'].append({'rule': 'invalid_request', 'severity': 'error',
                                  'detail': str(exc) if type(exc) is ValueError else type(exc).__name__})
    return report
