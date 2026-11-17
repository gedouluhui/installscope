# Implementation evidence

2026-11-18, owner-run Windows x64 / Python 3.12.3, standard-library runtime.

- Core RED: 17 unittest methods produced 24 failures including subtests because audit_wheels was absent. Local ignored evidence is artifacts/core-red.log.
- Core GREEN: the same 17 tests passed after actual archive parsing, RECORD validation, destination mapping and ownership analysis were implemented.
- Additional RED: directory-count mismatch was accepted, member-count limits ran after ZipFile allocation, and a failed input reset the effective remaining-budget accounting. A fixture initially searched for literal backslash escape text instead of ZIP signature bytes; it was corrected first, then the actual product failure was reproduced.
- Added bounded central-directory preflight before ZipFile; reject ZIP64/multi-disk directory records; stop on the first invalid wheel, preserving previous evidence. The 20-test core suite passed.
- CLI/report RED: three tests failed for missing CLI/report behavior. After implementation, the combined 23 tests passed and `python -m installscope demo --output artifacts/demo` produced real CLEAR/CONFLICT reports.
- Independent installer oracle: `PYTHONPATH=src python -m unittest discover -s tests -p test_installer.py -v` passed. pip installed only two self-generated harmless packages into separate temporary targets with --no-index --no-deps --no-compile; their root and .data/purelib files reached the same relative path, matching the analyzer.
- Report-limit retention had a separate failing assertion before the limits fields were added.

The analyzer does not run pip or execute .pth contents. Its no-execution test starts with an absent marker, audits an input containing a harmless marker-writing import line, confirms absence, and separately executes the exact test line as a positive control. No existing environment is modified.

Limits: declared virtual payload destinations only; no generated wrappers/pyc, installed-environment snapshot, dependency/ABI/CVE analysis or complete filesystem/installer model. Windows casefold is explicitly a policy, not exact OS behavior. Independent code review, final full-suite run, build and visual checks follow separately.

## Independent review and correction round

The reviewer found three concrete parser-boundary problems and a CI omission. The owner reproduced all defects with named red tests: a ZIP64 directory concealed inside an ordinary central-directory entry could override preflight; ZipExtFile clipped a much larger deflate stream to a forged one-byte length, hiding expansion; Windows ambiguity rejection applied to members but not scheme roots; CI lacked a built-wheel outside-checkout verification step.

Corrections: reject a ZIP64 locator exactly where Python's directory selector recognizes it, then verify the selected directory range/count; decode stored/deflate payloads with a bounded raw reader before any declared-size clipping, validating headers, extents, actual output, CRC, end-of-stream and data descriptors; use the same Windows component validation for scheme roots and members, with ordinary-drive roots only; add scripts/check_distribution.py and execute it after wheel build in CI.

Controls include a standard-parser positive demonstration of hidden directory selection and clipped output, valid stored/deflated seekable and streaming-descriptor wheels, CRC corruption, and a guard proving the analyzer no longer calls ZipExtFile.open for payloads. The owner additionally reproduced and rejected unsupported encryption/patch flags during the new raw-reader transition.

The attempted independent fix re-review did **not start**: the agent service returned a daily billing/count limit (zero tool calls). It was not silently rerouted to another identity. Therefore the first independent review occurred, but the corrected version has owner verification rather than a second independent approval.

The owner added raw-record controls independent of the wheel fixture builder: stored/deflated and data-descriptor combinations, empty and large random/compressible data across 64-KiB boundaries, trailing compressed bytes, truncated streams, wrong descriptors and output-budget refusal. Latest full-suite command `PYTHONPATH=src python -m unittest discover -s tests -v`: 38 tests passed. The distribution checker was exercised on a freshly built correction-stage wheel and confirmed source bytes, payload allowlist and installed CLI outside the checkout. Final wheel verification is recorded separately below.

This review gap remains explicit. No full ZIP-security or filesystem-sandbox certification is claimed.

## Final installed-package verification

The owner rebuilt only this still-unreleased project, checked packaged module bytes against current source, installed into a temporary target, and ran all 38 tests outside the source checkout. Disabling file-collision handling in an isolated copy was caught by `test_root_and_data_remap_collide`; original source hashes were unchanged. The repository's own distribution verifier then passed its payload allowlist, source-byte and outside-checkout CLI checks.

The final installed CLI's collision report was opened in Chrome at actual emulated 360 and 1200 CSS pixel viewports, with the page visibly selected. Root horizontal overflow was absent, details changed from closed to open, both owners and eight inventory rows were visible, and no external resource timing entries were observed. No saved screenshot asset or cross-browser/accessibility certification is claimed.

Machine-readable source/wheel fingerprints, generator fingerprint, mutation evidence, visual observations and the independent-review limitation: [verification.json](verification.json).
