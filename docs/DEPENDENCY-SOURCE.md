# Dependency source and binary-distribution plan

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Public-distribution verdict: HOLD
Release-gate-status: HOLD
Qualified-review-status: HOLD
Audit-blocker-count: 6

Audit date: 2026-07-22  
Target: Neural Extractor V3.0.8, Windows x64, PyInstaller one-file

This is an engineering source-closure plan, not a source offer, legal advice,
or a claim of compliance. It must remain HOLD until every listed blocker is
closed and a qualified reviewer approves the final distribution set.

## Authoritative records

- `THIRD_PARTY_LICENSES.txt`: artifact-derived component, file, version,
  license, holder, source, modification, action, and boundary inventory.
- `requirements.lock`: exact Python requirements with hashes.
- `uv.lock`: complete resolved Python lock and source metadata.
- `SOURCE-HASHES.sha256`: exact local application/build/document input hashes.
- `licenses/RELEASE-LICENSE-MANIFEST.sha256`: every distributed license and
  notice file, with SHA-256.
- `NeuralExtractorV3.spec`: exact file-selection and native hash gates.
- `scripts/generate_distribution_inventory.py`: deterministic artifact
  inventory and non-compliance-payload fingerprint.
- `scripts/verify_distribution_boundary.py` and
  `scripts/verify_packaged_licensing.py`: source and frozen-archive gates.

The embedded inventory is generated in `--embeddable` mode and omits the size
and hash of its enclosing EXE. A post-build sidecar inventory must add the final
outer size and SHA-256 while reproducing the embedded non-compliance payload
fingerprint.

## Main distribution boundary

The main EXE contains OpenFetch, CPython, PyInstaller runtime support,
PySide6/Qt/Shiboken, locked Python packages, Node.js, FFmpeg/ffprobe, and
Microsoft runtime files enumerated in `THIRD_PARTY_LICENSES.txt`.

It contains no PyQt package and no `bgutil-ytdlp-pot-provider` Python,
JavaScript, TypeScript, npm, canvas, source-map, or native payload. The optional
provider helper is not included in the EXE, release ZIP, source companion, or
updater assets. It is a separate distribution with a separate audit.

## Exact retained source/provenance evidence

| Component/input | Exact version or revision | Retained or verified SHA-256 | Status/action |
|---|---|---|---|
| CPython source | 3.12.9, `Python-3.12.9.tar.xz` | `7220835d9f90b37c006e9842a8dff4580aaca4318674f947302b8d28f3f81112` | Retain source and all historical/component notices. |
| python-build-standalone binary asset | release 20250317 | `ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661` | Exact install-only asset; retain recipe/patch/toolchain sources too. |
| python-build-standalone recipe archive | commit `7d8bb5e8cf054d88cbf505645257a25b8f46b286` | `0f2d76ea433930d72e94541b6edfecbf2a6d26fb811adc681be92f17d07ff4b4` | Retain MPL-2.0 recipes, patches, notices, and reconstruction steps. |
| CPython `_ctypes.pyd` | 3.12.9 standalone build | `6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41` | Build gate; must load the exact root libffi below. |
| CPython `libffi-8.dll` | libffi 3.4.2 | `d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e` | Exactly one root copy; retain source/build provenance. |
| PySide/PySide6/Shiboken source | 6.11.1, `pyside-setup-everywhere-src-6.11.1.tar.xz` | `6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2` | Retain exact source, license set, notices, and build/relink instructions. |
| QtBase source | 6.11.1, `qtbase-everywhere-src-6.11.1.tar.xz` | `d9594a31228aa23ad6b531719a29b45f0f3989fe6c136d45767ea179f233c1ac` | Retain exact source, Qt attributions, license set, and selected third-party source. |
| setuptools source | 83.0.0 tar.gz | `025bccbbf0fa05b6192bc64ae1e7b16e001fd6d6d4d5de03c97b1c1ade523bef` | Retain exact source plus all selected vendor/generated notices and MPL inputs. |
| Node.js source | 22.17.0, `node-v22.17.0.tar.gz` | `f8bf095ff559033edf04108fb1f14f72e2be337c609d4f83e8af1e299af7f4b4` | Retain source and the complete Node license/third-party notice file. |
| Node.js Windows executable | 22.17.0 | `39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636` | Exact hash enforced by the spec. |
| FFmpeg executable | `N-125365-g9a01c1cb6a-20260630` | `6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e` | Binary provenance known; full source/toolchain closure still missing. |
| ffprobe executable | same BtbN build | `55a3d20229c2373dade4362215c9bd5a04b59d4e734d0bbb882afd9cea4fb046` | Binary provenance known; full source/toolchain closure still missing. |
| BtbN binary archive | `ffmpeg-N-125365-g9a01c1cb6a-win64-gpl.zip` | `52c0383c460f0ec1039088f1591921fb82e3b870b32aab8faf2ff1e5ae14bf9d` | Retain exact binary archive and bind it to complete Corresponding Source. |

The candidate FFmpeg commit-source hashes recorded during the audit are
`8ca7287b2659c2309ad5060caad5b9ae4ef51f1b54ed5a30e0bfc815ee1c376d`
(ZIP) and
`b752d9b889d87ff96522438450268b1cfad449f4a8e66ff5058432636f491129`
(tar.gz) for commit `9a01c1cb6a4cf87529fe9898b66ec55c5b032639`.
The BtbN script commit `7a83528ea3431e9eca982a712bc3a7cd0789d5d0`
had candidate hashes
`14e560e13dea71189bd317be0b6c3fe5ba42b74c5a73a6b5952ddf44d5225e99`
(ZIP) and
`0f0f15e02b4fd1b1bc37d2e3a6f57cd7a2078c31a51c8546110d3ccb40029d30`
(tar.gz). These candidates are not a complete or currently retained source
companion. The BtbN recipe has additional linked libraries and historically
floating inputs that must be resolved and retained exactly.

## Python package closure

The main runtime lock pins `yt-dlp==2026.7.4`, `PySide6==6.11.1`,
`pillow==12.3.0`, `requests==2.34.2`, and
`youtube-transcript-api==1.2.4`. The artifact contains the exact resolved
runtime packages identified as `MAIN EXE` in `THIRD_PARTY_LICENSES.txt`,
including PySide6-Essentials, Shiboken6, certifi, charset-normalizer, idna,
urllib3, packaging, typing_extensions, and selected setuptools 83.0.0
vendored/generated code. Pillow, youtube-transcript-api, and its defusedxml
dependency are locked inputs whose package code is absent from the audited PYZ;
only their preserved notice evidence is included. PySide6-Addons 6.11.1 is also
a locked installation input, but its Qt Addons modules are excluded from the
frozen payload.

For each frozen Python distribution, retain:

1. the exact wheel and source distribution identified by `requirements.lock`
   and `uv.lock`;
2. all license, copyright, NOTICE, attribution, and public-domain texts;
3. build backend, generator, patch, and toolchain material needed to reproduce
   conveyed native/generated files; and
4. a manifest linking the exact artifact paths to those inputs.

The local `licenses/python/` closure contains 55 collected metadata/license
files. It must be regenerated and validated whenever the lock or candidate
payload changes.

## CPython and native transitive closure

The CPython 3.12.9 standalone runtime contains or links libffi 3.4.2, OpenSSL
3.0.16, SQLite 3.47.1, bzip2 1.0.8, XZ/liblzma 5.2.12, zlib 1.3.1, Expat
2.6.4, mpdecimal 2.5.1, a HACL* snapshot, Unicode 15.0.0 data, and
BLAKE2-derived code. Exact observed paths and licenses are recorded in the
inventory.

The CPython source and standalone recipe evidence is not yet a complete
transitive source package. Exact source archive hashes and applicable notices
are still required for at least OpenSSL, SQLite, bzip2, XZ/liblzma, zlib,
Expat, Unicode data, and any other selected standalone-build input not fully
covered and identified by the pinned CPython tree. Preserve the standalone
patches, compiler/toolchain inputs, and reconstruction instructions.

## PySide6/Qt source and replacement material

The only selected Qt libraries are Qt6Core, Qt6Gui, and Qt6Widgets, plus
`qwindows`, `qoffscreen`, `qico`, `qmodernwindowsstyle`, and
`opengl32sw`. No Qt translations or Addons modules are included. Exact paths,
sizes, and hashes are in the inventory.

The planned LGPL route requires, subject to qualified review:

- the unmodified LGPLv3 text and all selected Qt/PySide/Shiboken notices;
- exact PySide and QtBase 6.11.1 source, including applicable third-party source
  and attribution material for the selected binaries and software-render
  fallback;
- the project source and PyInstaller/build scripts used to combine the work;
- a practical, independently tested way for a recipient to replace/relink the
  covered libraries and run the modified result; and
- no contractual or technical restriction on reverse engineering needed to
  debug such modifications.

The current one-file replacement/relink procedure has not been independently
demonstrated. Source archives and notices alone do not close that blocker.

## FFmpeg source delivery

The included FFmpeg/ffprobe binaries report `--enable-gpl --enable-version3`
and no `--enable-nonfree`; the recorded distribution route is GPL-3.0-or-later.
Before conveyance, retain and serve under distributor control the exact FFmpeg
source, BtbN scripts/configuration, local modifications, linked-library source
and notices, compiler/crosstool/container inputs, and complete build/install
instructions. Bind every source input to the binary hashes above.

The current repository does not contain a complete validated Corresponding
Source package or a valid distributor-controlled delivery method. Upstream
project links are evidence of provenance, not a substitute for the required
source delivery.

## Node.js and npm

The main EXE contains `bin/node.exe` 22.17.0 and its complete local Node license
file, but no npm project or `node_modules` tree. Node's bundled third-party
notices must remain intact and its exact source archive must be retained.

The separately installed optional provider helper has 184 npm package records
and a canvas/MSYS2 native closure. Those dependencies are outside this main-EXE
plan. If that helper is separately distributed, it needs its own complete GPL,
npm, canvas, native, Rust/librsvg, source, build, notice, and relink package.
Its public distribution currently remains HOLD.

## Microsoft runtime files

The inventory records every root, PySide6-scoped, and Shiboken6-scoped VC/UCRT
file with path, version where readable, size, and SHA-256. Before release,
confirm that every exact file was obtained from an authorized redistributable
source and is covered by the applicable Microsoft terms. Preserve those terms.
Authenticode or a matching hash alone does not establish redistribution rights.

## Required binary companion

The intended layout is a plan, not an approved offer:

```text
NeuralExtractorV3-3.0.8-windows-x64.exe
NeuralExtractorV3-3.0.8-windows-x64.sha256
THIRD_PARTY_LICENSES-artifact-companion.txt
LICENSE
THIRD_PARTY_NOTICES.md
THIRD_PARTY_LICENSES.txt
docs/
  DEPENDENCY-SOURCE.md
  BUILD-REPRODUCIBILITY.md
  LGPL-COMPLIANCE.md
licenses/
  RELEASE-LICENSE-MANIFEST.sha256
  [all exact applicable license/notice/attribution files]
corresponding-source/
  application-source-and-build-scripts/
  python-runtime-and-python-build-standalone/
  python-distributions-and-generated-vendor-source/
  pyside6-qtbase-source-notices-and-relink-material/
  node-22.17.0-source-and-notices/
  ffmpeg-btbn-linked-libraries-toolchain-and-build-scripts/
  SOURCE-MANIFEST.sha256
  BUILDING.md
  INSTALLING-MODIFIED-LGPL-LIBRARIES.md
```

Do not put the optional provider helper or its source/npm/native closure in the
main release ZIP or updater assets. A distributor who separately conveys that
helper must prepare a separately versioned companion and audit.

## Written source offers

No written source offer currently accompanies or cures this binary. Do not
publish one until the exact source set has been independently reconstructed and
tested. If a written-offer route is selected where legally available, a
qualified reviewer must confirm its applicable license section, covered
objects and recipients, duration, permissible charge, installation information
where relevant, and actual fulfillment process. An upstream URL by itself is
not recorded here as an offer by the distributor.

## Open blockers

The project-owned author, copyright period, and MIT-intent fields are resolved
in `PROJECT-METADATA.json` and
`docs/PROJECT-OWNERSHIP-DECLARATION.md`. That resolution does not close any
third-party source or legal-review condition below.

1. The one-file LGPL replacement/relink procedure is not independently tested.
2. Complete FFmpeg Corresponding Source and a distributor-controlled delivery
   method are absent.
3. The CPython/python-build-standalone transitive source and recipe closure
   needs final review and missing exact source hashes.
4. Microsoft runtime redistribution coverage for every inventoried DLL is
   unconfirmed.
5. Qt/PySide notice, attribution, source, and software-render fallback closure
   needs final review.
6. Qualified legal review has not approved the distribution or external-helper
   classification.

The public-release verdict remains HOLD even if all technical scans pass.
