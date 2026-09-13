# Qt, PySide6, and Shiboken6 build provenance

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: HOLD

This record describes the exact binaries selected for the local Windows x64
one-folder candidate. Unknown upstream build facts are identified explicitly;
none are inferred.

## Package inputs

| Package | Version | Windows x64 wheel SHA-256 |
|---|---:|---|
| PySide6 | 6.11.1 | `0968877ab1fb4ef3587a284da6fe05e8647ada56a6a3750b6395188e01f4aba6` |
| PySide6-Essentials | 6.11.1 | `63311bd48e32c584599ab04b9ef7c324082374cd2c9fa533f978fb893bb47e40` |
| PySide6-Addons (lock-only, not retained) | 6.11.1 | `0d13c4dfd671b050a48e4f8d8ddc724b7248f9c0437e7fc47fdf316278572923` |
| Shiboken6 | 6.11.1 | `c2c6863aa80ec18c0f82cea3417837b279cdc60024ac17123461dc9042577df7` |

The exact wheel URLs and all platform alternatives are pinned in `uv.lock`.
PySide6-Addons 6.11.1 is a lock-resolution input but no Addons module or binary
is retained in the candidate.

The one-folder verifier parses `uv.lock` as TOML and binds each package name and
version to its exact Windows wheel URL and hash. It also validates every one of
the 22 retained family files against its installed wheel `RECORD` size/hash and
the fixed audited binary baseline; arbitrary same-named PE files are rejected.

The local build uses CPython 3.12.9 from python-build-standalone 20250317 and
PyInstaller 6.21.0. `NeuralExtractorV3.spec` selects the wheel binaries without
patching, stripping, UPX compression, or binary rewriting. Project-declared
modifications to the upstream PySide, Shiboken, and Qt binaries: **none**.

## Official source baselines

| Source archive | Official URL | SHA-256 |
|---|---|---|
| `pyside-setup-everywhere-src-6.11.1.tar.xz` | `https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.11.1-src/pyside-setup-everywhere-src-6.11.1.tar.xz` | `6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2` |
| `qtbase-everywhere-src-6.11.1.tar.xz` | `https://download.qt.io/official_releases/qt/6.11/6.11.1/submodules/qtbase-everywhere-src-6.11.1.tar.xz` | `d9594a31228aa23ad6b531719a29b45f0f3989fe6c136d45767ea179f233c1ac` |

Both byte-identical archives are retained under
`third_party_sources/qt-pyside/`. Their locally recomputed hashes match this
table.

## Exact selected binary baseline

These are the source-wheel sizes and hashes expected before PyInstaller
collection. `QT-PYSIDE-COMPONENTS.json` records the final candidate copies.

| Candidate path | Bytes | SHA-256 |
|---|---:|---|
| `PySide6/MSVCP140.dll` | 549176 | `708dd7bbc7bd23bce9e93f7837a70c2dd7ad55cff43801e92c0f7fcd7dda47cd` |
| `PySide6/MSVCP140_1.dll` | 27448 | `b2113956aa3fcb9decfe65be1ee7829f8e3ae0899633ae89fe04888ada201594` |
| `PySide6/MSVCP140_2.dll` | 271672 | `1b806b427ffb573deff8478cf6fe336465fe2c67e0919bb95f452b6f31d25736` |
| `PySide6/opengl32sw.dll` | 20639544 | `4a7d90f91fdecb5df7b426bc2d05974b8d7ffa450af2d1f93f3eca05800718da` |
| `PySide6/plugins/imageformats/qico.dll` | 45880 | `f81378dd51392ff0d3ae094d5e59dfc4fa664a0ef4d756d6ed40584f90af2758` |
| `PySide6/plugins/platforms/qoffscreen.dll` | 113976 | `426266e8ba0ea07c416616ad9973702fe126d4559cb2ee11e1c9bdbae85ba755` |
| `PySide6/plugins/platforms/qwindows.dll` | 1006904 | `54d736de022f707e9f7f555e4c9f9e993253cd5b0ee2364e6a9458c180828c42` |
| `PySide6/plugins/styles/qmodernwindowsstyle.dll` | 230712 | `9af96b09ebaf7ff13e22c70bf69b9c3f226f069375d1a9f9efd63e944e43f5fb` |
| `PySide6/pyside6.abi3.dll` | 248632 | `d4072be872b31f3748de5e6c28cb2976dafbf063d3ccfa38e5dabda29babcdaf` |
| `PySide6/Qt6Core.dll` | 10480440 | `65fe6224b6c47a15b058738031d31dce9928c4d7a58e1b8db6434f6f5cddd702` |
| `PySide6/Qt6Gui.dll` | 9589560 | `cd071161ad325ff2de92b0e33d71334ef20712544796949623ce92dfb3957e90` |
| `PySide6/Qt6Widgets.dll` | 6594360 | `5a9f37dedd3dc5bcc1a4bb8ea919c49fc62df751a1450accc34379eb6710eab6` |
| `PySide6/QtCore.pyd` | 3330360 | `be52341a5df1f76ecca2fb1e94eb429dfa46f0b659ed6536f25119b565b21ea8` |
| `PySide6/QtGui.pyd` | 3896632 | `f0549716b10a8b4fbd5c6c041f36af215223809f919f4c4722d44cc199d5c593` |
| `PySide6/QtWidgets.pyd` | 4856120 | `85cb6c2181b4b09887a7d8507dd950844d1b8f74a9c4002c7b71169f75bf6fda` |
| `PySide6/VCRUNTIME140.dll` | 116024 | `c6e841078cd352299a58925991e2552f7251b046253ba895b3ad50cd5cd32ec6` |
| `PySide6/VCRUNTIME140_1.dll` | 41272 | `b322e382ea249b50009f14a9a71ad16729eb6e4b58a8d3b3be6ac66ea6342a22` |
| `shiboken6/MSVCP140.dll` | 549176 | `005f2324c7ff79bbe9a44992b0708abb4c871bd24bcc7a34aca5eab4439c1f4a` |
| `shiboken6/Shiboken.pyd` | 33080 | `0e2c5318c5ac60a016a12230bbb1f6a9d990c45cbf4a7c4af24aefb5ab7dc40a` |
| `shiboken6/shiboken6.abi3.dll` | 384824 | `47f4f9b44c95037565dd14f4be04f350f20c53c05483b750e0be867c39a7441e` |
| `shiboken6/VCRUNTIME140.dll` | 116024 | `8d9c679c825c5fff298d66c41af30f35c289fc101868dfc9635547bada0daba6` |
| `shiboken6/VCRUNTIME140_1.dll` | 41272 | `e4d7ea5f4f4ff6d0c208e693853617cdef0ad71cfe5dd5c3ae16c8a6b64c18ea` |

The Microsoft paths in this table are provenance facts, not an assertion of a
Qt/PySide license or redistribution right.

## Selection/configuration performed by this project

- imported modules: QtCore, QtGui, QtWidgets;
- retained plugins: `qwindows`, `qoffscreen`, `qico`,
  `qmodernwindowsstyle`;
- retained software renderer: `opengl32sw.dll`;
- excluded: translations and all unused Qt/PySide modules/plugins;
- PyInstaller mode: one-folder `COLLECT`, uncompressed external shared files;
- UPX: disabled;
- local Qt/PySide source patches: none;
- local Qt/PySide binary patches: none;
- deterministic environment: `PYTHONHASHSEED=0`, `SOURCE_DATE_EPOCH=0`.

## Upstream build facts not yet evidenced

The PyPI wheels do not, by themselves, provide the local audit with all of the
following exact facts:

- Qt configure command and feature summary;
- MSVC compiler/toolset and Windows SDK build numbers;
- CMake/Ninja and other build-tool versions;
- patches and generated-source inputs used for the wheel binaries;
- exact software-renderer/Mesa/LLVM provenance for `opengl32sw.dll`;
- a demonstrated rebuild producing an ABI-compatible complete replacement set.

Until these are recovered or independently reconstructed and reviewed, this
provenance record is incomplete for a public LGPL compliance conclusion and the
release remains **HOLD**.

In particular, the PySide and QtBase archives alone are not claimed to be the
complete corresponding source for `opengl32sw.dll` or every incorporated Qt
third-party binary. The native binary-to-source map and source bundle must close
those relationships independently.

## Local one-folder audit artifact

The 2026-07-22 technical candidate (not approved for publication) produced:

- directory: `NeuralExtractorV3-3.0.8-windows-x64`, 457 files,
  473,754,371 bytes;
- executable: 10,304,447 bytes, SHA-256
  `9b1e1e8dfebbcd92bc405900e4d9ad3fe160ee0bd0f2750a028d84b0d9f7bd62`;
- deterministic ZIP: 190,094,251 bytes, SHA-256
  `3cd905c68d482a653029586343b4462734dffb4531a456c45a4c84fafce0c918`.

The packaged Qt/PySide replacement/rollback smoke, Windows/offscreen GUI
smokes, provider-absent scan, and CPython libffi/Node/FFmpeg runtime smoke all
passed. This artifact predates final integration of the other compliance
workstreams and is test evidence only, not a release candidate approved for
public distribution.
