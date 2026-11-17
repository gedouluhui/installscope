"""Portable escaped evidence, safe local output, no JavaScript."""
from html import escape
import json
import os
from pathlib import Path
import tempfile


def validate_outputs(paths, inputs=()):
    outputs = [Path(p) for p in paths if p is not None]
    known = [Path(p) for p in inputs]
    for path in outputs:
        if path.is_symlink() or not path.parent.is_dir() or (path.exists() and not path.is_file()):
            raise ValueError('report paths need an existing parent and cannot be symlinks/directories')
        if any(path.resolve() == p.resolve() or
               (path.exists() and p.exists() and os.path.samefile(path, p)) for p in known):
            raise ValueError('report path aliases an input or another output')
        known.append(path)


def atomic_write(path, content):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.installscope-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def to_html(report):
    e = lambda x: escape(str(x), quote=True)
    findings = []
    for f in report['findings']:
        owners = ''.join('<li><b>' + e(i['owner']) + '</b> <code>' + e(i['member']) + '</code></li>' for i in f.get('owners', []))
        findings.append('<article><span class="tag">' + e(f['severity']) + '</span><h3>' + e(f['rule']) + '</h3><p>' + e(f['detail']) +
                        '</p><ul>' + owners + '</ul><div class="destination">' + e(f.get('destination', f.get('input', f.get('member', '')))) + '</div></article>')
    rows = ''.join('<tr><td>' + e(i['owner']) + '</td><td><code>' + e(i['member']) + '</code></td><td><code>' + e(i['destination']) +
                   '</code></td><td>' + e(i['kind']) + '</td></tr>' for i in report['inventory'])
    raw = e(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False))
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>InstallScope · Destination ownership</title><style>*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#1d2b43;font:16px/1.6 system-ui,sans-serif}main{max-width:1160px;margin:auto;padding:48px 24px}.brand{font:600 14px ui-monospace,monospace;letter-spacing:.12em;color:#425aa2}header{border-bottom:2px solid #425aa2;padding-bottom:24px}h1{font:500 clamp(32px,6vw,56px)/1.15 Georgia,serif;margin:20px 0}.status{background:#1d2b43;color:#fff;display:inline-block;padding:7px 16px}h2{margin-top:36px}.scope{background:#e8edf6;padding:18px;border-left:3px solid #425aa2}article{background:white;padding:20px;margin:16px 0;border:1px solid #d7deeb}h3{margin:6px 0}article ul{list-style:none;margin:12px 0;padding:0}article li{padding:9px;border-left:2px solid #425aa2;background:#f5f7fa;margin:6px 0}.destination{border-top:2px solid #9b431a;padding:10px;color:#9b431a;font:14px ui-monospace,monospace;overflow-wrap:anywhere}.tag{font:12px ui-monospace,monospace;color:#9b431a}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;background:white}th,td{border-bottom:1px solid #d7deeb;text-align:left;padding:11px;vertical-align:top}th{font-size:13px}code{font:12px/1.6 ui-monospace,monospace;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#e8edf6;padding:20px;font-size:12px}summary{cursor:pointer}summary:focus-visible{outline:3px solid #425aa2}footer{margin-top:36px;font-size:13px;color:#52637d}@media(max-width:600px){main{padding:24px 14px}}</style><main><header><div class="brand">INSTALLSCOPE / PAYLOAD OWNERSHIP</div><h1>Different packages.<br>The same destination?</h1><span class="status">''' + e(report['status']) + '''</span></header><p class="scope">''' + e(report['scope']['meaning']) + '''</p><h2>Ownership findings</h2>''' + (''.join(findings) or '<p>No conflict in the declared payload write set.</p>') + '''<h2>Installation map</h2><div class="scroll"><table><tr><th>Owner</th><th>Inside wheel</th><th>Virtual destination</th><th>Kind</th></tr>''' + rows + '''</table></div><details><summary>Scope, hashes, limits and complete JSON</summary><pre>''' + raw + '''</pre></details><footer>Inspected locally without installing or executing the supplied wheels. RECORD consistency does not prove package trustworthiness.</footer></main></html>'''
