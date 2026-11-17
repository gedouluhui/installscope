"""Pure lexical destination mapping, never a filesystem write."""
from pathlib import PurePosixPath, PureWindowsPath
import re

from .archive import member_name

KEYS = {'purelib', 'platlib', 'scripts', 'headers', 'data'}


def validate_windows_component(part):
    if (part.endswith((' ', '.')) or any(ord(c) < 32 or c in ':<>"|?*' for c in part)
            or re.fullmatch(r'(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])', part.split('.')[0])):
        raise ValueError('unsupported or ambiguous Windows path component')


class Scheme:
    def __init__(self, platform='posix', values=None):
        if platform not in ('posix', 'windows'):
            raise ValueError('platform must be posix or windows')
        self.platform = platform
        if values is None:
            if platform == 'posix':
                values = dict(purelib='/venv/lib/python/site-packages', platlib='/venv/lib/python/site-packages',
                              scripts='/venv/bin', headers='/venv/include', data='/venv')
            else:
                values = dict(purelib='C:/venv/Lib/site-packages', platlib='C:/venv/Lib/site-packages',
                              scripts='C:/venv/Scripts', headers='C:/venv/Include', data='C:/venv')
        if not isinstance(values, dict) or set(values) != KEYS:
            raise ValueError('scheme must explicitly supply purelib, platlib, scripts, headers and data')
        cls = PurePosixPath if platform == 'posix' else PureWindowsPath
        for value in values.values():
            if not isinstance(value, str) or not cls(value).is_absolute() or '..' in cls(value).parts:
                raise ValueError('scheme roots must be absolute virtual paths without traversal')
            if platform == 'windows':
                parsed = cls(value)
                if not re.fullmatch(r'[A-Za-z]:', parsed.drive):
                    raise ValueError('Windows scheme supports ordinary drive roots only, not UNC/device namespaces')
                for component in parsed.parts[1:]:
                    validate_windows_component(component)
        self.values = {k: cls(v).as_posix().rstrip('/') for k, v in values.items()}

    def destination(self, wheel, item):
        name = member_name(item['member'])
        pieces = name.split('/')
        if self.platform == 'windows':
            for part in pieces:
                validate_windows_component(part)
        top = pieces[0]
        key = 'purelib' if wheel['root_is_purelib'] else 'platlib'
        if top.endswith('.data'):
            if top != wheel['distribution'] + '-' + wheel['version'] + '.data':
                raise ValueError('unexpected .data root')
            if len(pieces) == 1 and item['kind'] == 'directory':
                return None
            if len(pieces) < 2 or pieces[1] not in KEYS:
                raise ValueError('unsupported .data installation category')
            key = pieces[1]
            pieces = pieces[2:]
            if not pieces and item['kind'] == 'file':
                raise ValueError('file cannot replace an installation scheme root')
        path = self.values[key] + ('/' + '/'.join(pieces) if pieces else '')
        return path.casefold() if self.platform == 'windows' else path
