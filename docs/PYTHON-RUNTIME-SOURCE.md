# Python runtime source record

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: **HOLD**

Exact-byte-provenance-status: **MATCH**

Clean-rebuild-status: **NOT ESTABLISHED**

Qualified-review-status: **REQUIRED**

This is an engineering source/provenance record, not legal advice. It covers
the CPython and native-library bytes taken from the
python-build-standalone (PBS) 20250317 Windows x64 runtime used for Neural
Extractor V3.0.8.

## Runtime identity

- CPython: 3.12.9
- PBS release: 20250317
- target: `x86_64-pc-windows-msvc`
- exact upstream input:
  `cpython-3.12.9+20250317-x86_64-pc-windows-msvc-install_only_stripped.tar.gz`
- input SHA-256:
  `ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661`
- PBS recipe commit: `7d8bb5e8cf054d88cbf505645257a25b8f46b286`

`third_party_sources/python-runtime/RUNTIME-ASSET-COMPARISON.json` compares 26
conveyed native files against members of that exact runtime archive. All 26
match in size and SHA-256. This includes 24 CPython/native-library files and the
two root `VCRUNTIME140*.dll` files. A byte match proves the immediate archive
provenance; it does not prove a clean source rebuild or redistribution rights.

## Retained actual build sources and inputs

| Component/input | Version or commit | Role | SHA-256 |
|---|---|---|---|
| CPython | 3.12.9 | Actual source | `7220835d9f90b37c006e9842a8dff4580aaca4318674f947302b8d28f3f81112` |
| PBS recipes/patches | `7d8bb5e8cf054d88cbf505645257a25b8f46b286` | Actual recipe snapshot | `0f2d76ea433930d72e94541b6edfecbf2a6d26fb811adc681be92f17d07ff4b4` |
| PBS runtime asset | 20250317 | Exact binary input | `ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661` |
| `cpython-source-deps` / libffi | `16fad4855b3d8c03b5910e405ff3a04395b39a98` / 3.4.2 | Actual libffi snapshot | `f21ae7b0cce58cf9428e01d4d22aac9c3b70722a4e9b2c92b3a97d490a1b401c` |
| OpenSSL | 3.0.16 | Actual source | `57e03c50feab5d31b152af2b764f10379aecd8ee92f16c985983ce4a99f7ef86` |
| SQLite | 3.47.1 (`3470100`) | Actual source | `416a6f45bf2cacd494b208fdee1beda509abda951d5f47bc4f2792126f01b452` |
| bzip2 | 1.0.8 | Actual source | `ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269` |
| XZ/liblzma | 5.2.12 | Actual PBS source | `61bda930767dcb170a5328a895ec74cab0f5aac4558cdda561c83559db582a13` |
| zlib | 1.3.1 | Actual source | `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23` |
| Unicode Character Database | 15.0.0 | Generator/reference input | `5fbde400f3e687d25cc9b0a8d30d7619e76cb2f4c3e85ba9df8ec1312cb6718c` |
| setuptools | 83.0.0 | Frozen-package source; also tracked in package closure | `025bccbbf0fa05b6192bc64ae1e7b16e001fd6d6d4d5de03c97b1c1ade523bef` |
| Strawberry Perl portable | 5.38.2.2 | OpenSSL build tool binary | `ea451686065d6338d7e4d4a04c9af49f17951d15aa4c2e19ab8cb56fa2373440` |
| NASM CPython bin-deps | 2.11.06 | OpenSSL build tool binary | `8af0ae5ceed63fa8a2ded611d44cc341027a91df22aaaa071efedc81437412a5` |
| jom | 1.1.4 | OpenSSL build tool binary | `d533c1ef49214229681e90196ed2094691e8c4a0a0bef0b2c901debcb562682b` |

The authoritative paths, sizes, expected hashes, actual hashes, and verification
flags are in `third_party_sources/python-runtime/SOURCE-MANIFEST.json`. It also
hashes the extracted recipe tree and retained license set file-by-file.

Supplemental, non-controlling copies are retained for Expat 2.6.4, the upstream
XZ 5.2.12 release, and an alternate archive of the PBS recipe commit. The
runtime's actual Expat source is the copy vendored under
`Python-3.12.9/Modules/expat`; the runtime's actual XZ input is the PBS archive
listed above. The distinction is recorded in `supplemental_records` and avoids
substituting a convenient source archive for the source actually selected by
the recipe.

## Native components and terms

| Component | Runtime form | Engineering license classification | Preserved evidence |
|---|---|---|---|
| CPython | `python3.dll`, `python312.dll`, `.pyd` modules | PSF License Agreement plus historical notices | `LICENSE.cpython.txt`, `python-licenses.rst` |
| libffi | `libffi-8.dll`, `_ctypes.pyd` | MIT | `LICENSE.libffi.txt` |
| OpenSSL | `libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `_ssl.pyd`, `_hashlib.pyd` | Apache-2.0 for OpenSSL 3 | `LICENSE.openssl-3.txt` |
| SQLite | `sqlite3.dll`, `_sqlite3.pyd` | Public-domain dedication/SQLite notice | `LICENSE.sqlite.txt` |
| bzip2 | statically used by `_bz2.pyd` | bzip2 permissive license | `LICENSE.bzip2.txt` |
| XZ/liblzma | statically used by `_lzma.pyd` | Source-exact XZ notices; file-level terms apply | `LICENSE.liblzma.txt`, source archive notices |
| Expat | statically used by `pyexpat.pyd` | MIT | `LICENSE.expat.txt` |
| mpdecimal | statically used by `_decimal.pyd` | BSD-2-Clause | `LICENSE.mpdecimal.txt` |
| zlib, HACL*, BLAKE2, Unicode data | CPython runtime code/data | Component-specific permissive/public-domain/Unicode terms | CPython source, `python-licenses.rst`, retained source headers |

This table is a routing aid, not a substitute for reviewing the exact upstream
texts and source headers. All 21 PBS license/notice files are preserved under
`third_party_sources/python-runtime/licenses/` without rewriting their terms.

## Modifications

No OpenFetch modification to CPython, PBS, or the named native dependency
sources is declared. The distribution repackages selected upstream runtime
files through PyInstaller. The exact upstream PBS patches and transformations
are retained in `python-build-standalone-recipes/`; they remain upstream
modifications and must not be described as OpenFetch-authored changes.

## Distribution action

For a candidate distribution, keep the runtime source manifest, exact upstream
license texts, native component inventory, PBS recipes/patches, and actual
source archives together with the build/source package. Do not replace a
third-party term with the OpenFetch license. Microsoft runtime rights are
separate and remain HOLD under `docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md`.

Public distribution remains HOLD until the clean-rebuild gaps in
`docs/PYTHON-RUNTIME-REPRODUCIBILITY.md`, the Microsoft entitlement gaps, and
qualified review are closed.
