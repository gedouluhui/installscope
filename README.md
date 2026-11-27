# InstallScope

[![CI](https://github.com/gedouluhui/installscope/actions/workflows/ci.yml/badge.svg)](https://github.com/gedouluhui/installscope/actions/workflows/ci.yml)

**Different wheel paths can install to the same file. See the owners before installing.**

InstallScope reads local Python wheels, validates their declared payloads and maps them into a **declared virtual installation scheme**. It explains cross-package file ownership conflicts without installing, importing or executing the supplied packages.

[中文说明](README.zh-CN.md)

## Try it in one minute

```sh
python -m pip install .
installscope demo --output demo
```

Open `demo/collision.html`. One package owns `shared/config.py`; another puts it under `.data/purelib/`. Both end up at the same destination. `demo/clear.html` shows the legitimate shared-namespace-directory control. The tiny wheels and reports are generated locally from actual analysis; choose a new output directory.

## Audit a wheelhouse selection

```sh
installscope audit first.whl second.whl --platform posix --json result.json --html result.html
```

```python
from installscope import audit_wheels
report = audit_wheels(["first.whl", "second.whl"], platform="windows")
assert report["status"] == "CLEAR", report["findings"]
```

Runtime dependencies: **Python standard library only**. No server, vulnerability database, API key or package-index request.

## The result is deliberately scoped

| Status / exit | Meaning |
|---|---|
| CLEAR / 0 | No conflict in the **declared payload write set**. Not an environment-safety certificate. |
| CONFLICT / 1 | Two payloads claim the same destination, or a file occupies a required directory. |
| ERROR / 2 | Invalid input, failed integrity checks, unsupported format or exceeded limits. Earlier findings remain visible. |
| INCOMPLETE / 3 | Reserved for future explicit partial-scan modes; v0.1 stops with ERROR rather than truncating. |

The report includes original paths, virtual destinations, owners, content hashes, input fingerprints, limits and coverage. Equal-content files with different owners still conflict: uninstalling one owner may remove a file another expects. Merely sharing a namespace **directory** is not a collision.

`.pth` import lines are reported as information with line number and hash, without executing or embedding the code. They are not automatically malicious; automatic loading depends on location and the interpreter's site processing.

## Declare the destination layout

`--platform posix` is case-sensitive. `--platform windows` uses a conservative Unicode casefold policy and rejects reserved/ambiguous names in both members and scheme roots; it is **not** an exact Win32 filesystem emulator. Windows scheme roots must be ordinary drive-absolute paths; UNC/device namespaces are not supported.

Defaults are virtual layouts printed in every report, not detected paths on your machine. Override with `--scheme scheme.json`:

```json
{
  "purelib": "/env/lib/python/site-packages",
  "platlib": "/env/lib64/python/site-packages",
  "scripts": "/env/bin",
  "headers": "/env/include",
  "data": "/env"
}
```

All five roots are required. Header and script destinations in real installers can be package-/installer-specific; provide the actual policy rather than assuming this example matches pip on every platform.

## Integrity and resource boundaries

- Checks duplicate names, traversal/absolute/backslash paths, metadata identity, supported digest/size records, symlinks, encryption and unsupported compression.
- A bounded central-directory scan runs **before** ZipFile creates its member objects; declared and observed counts must match. A ZIP64 locator at the position recognized by Python is rejected, including a hidden-directory override inside another entry's extra data.
- Payload decoding uses a bounded raw stored/deflate reader, not ZipExtFile's declared-length-clipped output. It checks local/central agreement, record extents, actual decoded size, CRC, end-of-stream and supported data descriptors. An output-size sentinel detects excess without materializing the hidden expansion.
- Defaults: 256 MiB total compressed input, 512 MiB expanded valid-input budget, 20,000 members, 2 MiB per metadata/`.pth` inspection buffer. Command options can lower/raise these explicit limits; this is not a process-RSS or time sandbox.
- Scanning stops at the first invalid input so an aborted input cannot repeatedly reuse the remaining byte budget. Summary bytes count validated inventories, not partial reads from the aborted input.
- v0.1 supports Wheel-Version 1.0, stored/deflated payloads and SHA-256/384/512 RECORD hashes. ZIP64 central directories and multi-disk archives are rejected. Input bytes must remain stable during inspection.
- CRC/RECORD consistency and SHA-256 identify bytes; **they do not prove origin, trustworthiness or absence of malware**. Python's ZIP implementation remains part of the trust boundary.

**Not checked:** installed environments, generated console wrappers, rewritten script contents, `.pyc` files, dependency resolution, ABI compatibility, arbitrary installer side effects or vulnerabilities. No deletion, automatic repair or package execution is performed by the analyzer.

## Verify it

```sh
python -m unittest discover -s tests -v
python -m pip install build
python -m build --wheel
python scripts/check_distribution.py
```

Tests cover actual ZIP corruption, remapping collisions, platform policy, legal namespaces, ownership of equal bytes, file/directory prefixes and no-execution controls. An independent pip oracle installs **only self-generated harmless wheels into separate temporary targets** and confirms root/`.data/purelib` mapping. This installation occurs only in the test, never in the analyzer. See [implementation evidence](docs/IMPLEMENTATION.md).

## Related work

[Wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/), [check-wheel-contents](https://pypi.org/project/check-wheel-contents/), wheel-inspect and pip-audit solve important adjacent problems. InstallScope focuses on declared **multi-wheel destination ownership**, not replacing these tools or claiming a new scanning algorithm.

Small reproducible bug reports and additional installer-policy fixtures are welcome. Do not upload private wheels or sensitive reports. AI-assisted implementation; MIT. No PyPI publication, broad security certification or real-user adoption is claimed.

## Quickstart and support

### Problem
Map local wheel payloads into a declared installation scheme and expose cross-package destination conflicts before installing anything.

### Install
```sh
python -m pip install .
```

### Success
```sh
installscope demo --output demo
```
Expected: The self-generated clear and collision controls are both classified correctly; exit 0.

### Deliberate failure
```sh
installscope audit demo/demo_a-1.0-py3-none-any.whl demo/demo_b-1.0-py3-none-any.whl --platform posix
```
Expected: The two payloads claim the same destination and the command exits 1.

### Evidence and coverage boundaries
Evidence includes actual ZIP corruption, remapping collisions, platform policy, legal namespaces, equal-byte ownership, file/directory prefixes, no-execution controls, and an independent pip oracle using only self-generated harmless wheels. CLEAR covers the declared payload write set, not overall environment safety.

### Support status
Version 0.1.0 supports Python 3.10+ with the standard library only. No PyPI publication or broad security certification is claimed. Maintenance is best-effort with no SLA.

### Limitations
Installed environments, generated wrappers, rewritten scripts, .pyc files, dependency resolution, ABI compatibility, arbitrary installer side effects, and vulnerabilities are not checked. CRC/RECORD and SHA-256 do not prove origin or absence of malware.
