"""Read wheel payloads with bounded decompression. Never extract or execute."""
import base64
import csv
from email.parser import BytesParser
from email.policy import default
import hashlib
import io
from pathlib import Path
import re
import stat
import struct
import zipfile

from .zipstream import iter_member


def normalize_name(name):
    return re.sub(r'[-_.]+', '_', name).lower()


def member_name(name):
    if not name or name.startswith('/') or '\\' in name or any(ord(c) < 32 for c in name):
        raise ValueError('unsafe ZIP member name')
    clean = name[:-1] if name.endswith('/') else name
    if not clean or any(p in ('', '.', '..') for p in clean.split('/')):
        raise ValueError('unsafe ZIP path components')
    return clean


def one_header(message, name):
    values = message.get_all(name, [])
    if len(values) != 1 or not str(values[0]).strip():
        raise ValueError('missing or duplicate metadata field: ' + name)
    return str(values[0]).strip()


def preflight_directory(raw, max_members, max_archive_bytes):
    """Bound central-directory objects before ZipFile materializes its inventory.

    v0.1 deliberately rejects ZIP64 directory records and multi-disk archives.
    """
    size = raw.seek(0, 2)
    if size > max_archive_bytes:
        raise ValueError('compressed archive budget exceeded')
    start = max(0, size - 65557)
    raw.seek(start)
    tail = raw.read(size - start)
    pos = tail.rfind(bytes([80, 75, 5, 6]))
    if pos < 0 or len(tail) - pos < 22:
        raise ValueError('ZIP end record missing')
    end_position = start + pos
    if end_position >= 20:
        raw.seek(end_position - 20)
        if raw.read(4) == bytes([80, 75, 6, 7]):
            raise ValueError('ZIP64 locator is unsupported, including hidden directory overrides')
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack('<4s4H2LH', tail[pos:pos + 22])
    if disk or cd_disk or disk_count != count or count == 65535 or cd_size == 4294967295 or cd_offset == 4294967295:
        raise ValueError('multi-disk or ZIP64 directory is unsupported')
    if count < 1 or count > max_members:
        raise ValueError('central-directory member limit exceeded')
    if pos + 22 + comment != len(tail) or cd_offset + cd_size != start + pos:
        raise ValueError('ambiguous central-directory extent')
    cursor, observed = cd_offset, 0
    while cursor < cd_offset + cd_size:
        raw.seek(cursor)
        data = raw.read(46)
        if len(data) != 46:
            raise ValueError('truncated central-directory entry')
        fields = struct.unpack('<4s6H3L5H2L', data)
        if fields[0] != bytes([80, 75, 1, 2]) or fields[13] != 0:
            raise ValueError('invalid central-directory entry')
        filename, extra, note = fields[10:13]
        if not 1 <= filename <= 4096 or fields[16] >= cd_offset:
            raise ValueError('central-directory name or local offset outside supported range')
        observed += 1
        cursor += 46 + filename + extra + note
        if observed > max_members or cursor > cd_offset + cd_size:
            raise ValueError('central-directory extent/member limit exceeded')
    if observed != count:
        raise ValueError('central-directory entry count disagreement')
    raw.seek(0)
    return cd_offset, count


def inspect_wheel(path, *, max_archive_bytes, max_uncompressed_bytes, max_members, max_metadata_bytes):
    path = Path(path)
    if not path.name.endswith('.whl'):
        raise ValueError('input must be a .whl file')
    parts = path.name[:-4].split('-')
    if len(parts) not in (5, 6) or not re.fullmatch(r'[A-Za-z0-9_.]+', parts[0]):
        raise ValueError('unsupported wheel filename')
    dist, version = parts[:2]
    if not re.fullmatch(r'[A-Za-z0-9_.!+]+', version):
        raise ValueError('unsupported wheel version token')
    compressed = path.stat().st_size
    if compressed > max_archive_bytes:
        raise ValueError('compressed archive budget exceeded')
    expanded = 0
    with path.open('rb') as raw:
        directory_offset, directory_count = preflight_directory(raw, max_members, max_archive_bytes)
        first = hashlib.file_digest(raw, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _hash_stream(raw)
        raw.seek(0)
        with zipfile.ZipFile(raw) as z:
            infos = z.infolist()
            if not infos or len(infos) > max_members:
                raise ValueError('ZIP member count outside limit')
            if z.start_dir != directory_offset or len(infos) != directory_count:
                raise ValueError('preflight and ZIP parser selected different directories')
            offsets = sorted(i.header_offset for i in infos)
            if len(set(offsets)) != len(offsets):
                raise ValueError('multiple entries reference the same local ZIP header')
            bounds = dict(zip(offsets, offsets[1:] + [directory_offset]))
            lookup, canonical = {}, set()
            for info in infos:
                clean = member_name(info.filename)
                if info.orig_filename != info.filename or clean in canonical:
                    raise ValueError('ambiguous or duplicate ZIP member')
                canonical.add(clean)
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError('nonregular ZIP member (including symlink) is unsupported')
                if info.flag_bits & ~0x80E or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError('encrypted or unsupported ZIP compression')
                lookup[info.filename] = info
            roots = {n.split('/')[0] for n in lookup if n.split('/')[0].endswith('.dist-info')}
            if len(roots) != 1:
                raise ValueError('wheel must have exactly one dist-info root')
            root = next(iter(roots))
            expected_root = dist + '-' + version + '.dist-info'
            if root != expected_root:
                raise ValueError('dist-info root disagrees with wheel filename')
            special = {root + '/RECORD', root + '/RECORD.jws', root + '/RECORD.p7s'}
            cache = {}

            def read_member(name, limit=None):
                nonlocal expanded
                info = lookup.get(name)
                if info is None or info.is_dir():
                    raise ValueError('required metadata file missing')
                if limit is not None and info.file_size > limit:
                    raise ValueError('metadata size limit exceeded')
                if info.file_size > max_uncompressed_bytes - expanded:
                    raise ValueError('expanded byte budget exceeded')
                data = bytearray()
                for block in iter_member(raw, info, bounds[info.header_offset], max_uncompressed_bytes - expanded):
                    expanded += len(block)
                    if expanded > max_uncompressed_bytes or (limit is not None and len(data) + len(block) > limit):
                        raise ValueError('actual expanded byte budget exceeded')
                    data.extend(block)
                return bytes(data)

            for name in (root + '/METADATA', root + '/WHEEL', root + '/RECORD'):
                cache[name] = read_member(name, max_metadata_bytes)
            metadata = BytesParser(policy=default).parsebytes(cache[root + '/METADATA'])
            wheel_meta = BytesParser(policy=default).parsebytes(cache[root + '/WHEEL'])
            if metadata.defects or wheel_meta.defects:
                raise ValueError('malformed wheel metadata')
            real_name = one_header(metadata, 'Name')
            if normalize_name(real_name) != normalize_name(dist) or one_header(metadata, 'Version') != version:
                raise ValueError('METADATA identity disagrees with filename')
            if one_header(wheel_meta, 'Wheel-Version') != '1.0':
                raise ValueError('only Wheel-Version 1.0 is supported')
            pure = one_header(wheel_meta, 'Root-Is-Purelib')
            if pure not in ('true', 'false') or not wheel_meta.get_all('Tag'):
                raise ValueError('invalid Root-Is-Purelib or missing Tag')
            records = {}
            for row in csv.reader(io.StringIO(cache[root + '/RECORD'].decode('utf-8'), newline='')):
                if len(row) != 3 or row[0] in records:
                    raise ValueError('malformed or duplicate RECORD row')
                member_name(row[0])
                records[row[0]] = row[1:]
            files = {n for n, i in lookup.items() if not i.is_dir()}
            if set(records) - files or files - set(records) - special:
                raise ValueError('RECORD and archive payload inventories disagree')
            if records.get(root + '/RECORD') != ['', '']:
                raise ValueError('RECORD must contain its own unhashed, unsized row')
            inventory = []
            startup = []
            for name, info in lookup.items():
                clean = member_name(name)
                if info.is_dir():
                    if info.file_size != 0:
                        raise ValueError('directory entries cannot contain payload bytes')
                    for block in iter_member(raw, info, bounds[info.header_offset], max_uncompressed_bytes - expanded):
                        expanded += len(block)
                    inventory.append({'member': clean, 'kind': 'directory', 'sha256': None, 'size': 0})
                    continue
                expected = records.get(name)
                algo = None
                if name not in special:
                    if not expected or '=' not in expected[0] or not expected[1].isdigit():
                        raise ValueError('payload requires a digest and size in RECORD')
                    algo, encoded = expected[0].split('=', 1)
                    if algo not in ('sha256', 'sha384', 'sha512'):
                        raise ValueError('unsupported RECORD digest algorithm')
                h = hashlib.sha256()
                record_hash = hashlib.new(algo) if algo else None
                size = 0
                pth = bytearray() if name.endswith('.pth') else None
                if name in cache:
                    chunks = (cache[name],)
                    counted = True
                else:
                    if info.file_size > max_uncompressed_bytes - expanded:
                        raise ValueError('expanded byte budget exceeded')
                    chunks = iter_member(raw, info, bounds[info.header_offset], max_uncompressed_bytes - expanded)
                    counted = False
                for block in chunks:
                    if not counted:
                        expanded += len(block)
                        if expanded > max_uncompressed_bytes:
                            raise ValueError('actual expanded byte budget exceeded')
                    size += len(block)
                    h.update(block)
                    if record_hash:
                        record_hash.update(block)
                    if pth is not None:
                        if len(pth) + len(block) > max_metadata_bytes:
                            raise ValueError('.pth inspection size limit exceeded')
                        pth.extend(block)
                if size != info.file_size:
                    raise ValueError('ZIP member size disagreement')
                if record_hash:
                    actual = base64.urlsafe_b64encode(record_hash.digest()).rstrip(b'=').decode('ascii')
                    if actual != encoded or size != int(expected[1]):
                        raise ValueError('RECORD digest or size mismatch: ' + clean)
                inventory.append({'member': clean, 'kind': 'file', 'sha256': h.hexdigest(), 'size': size})
                if pth is not None:
                    for number, line in enumerate(pth.decode('utf-8', errors='replace').splitlines(), 1):
                        if line.startswith(('import ', 'import\t')):
                            startup.append({'member': clean, 'line': number, 'line_sha256': hashlib.sha256(line.encode()).hexdigest()})
        raw.seek(0)
        last = hashlib.file_digest(raw, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _hash_stream(raw)
        if last != first:
            raise ValueError('input bytes changed during audit')
    return {'input': path.name, 'sha256': first, 'owner': normalize_name(real_name) + '@' + version,
            'distribution': dist, 'version': version, 'root_is_purelib': pure == 'true',
            'inventory': inventory, 'startup': startup, 'expanded_bytes': expanded,
            'archive_bytes': compressed, 'members': len(infos)}


def _hash_stream(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(65536), b''):
        h.update(block)
    return h.hexdigest()
