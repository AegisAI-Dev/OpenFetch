# Microsoft runtime redistribution record

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: **HOLD**

Exact-byte-mapping-status: **52 OF 52 MATCH OBSERVED BUILD INPUTS**

Redistribution-rights-status: **NOT CONFIRMED**

Qualified-review-status: **REQUIRED**

This is an engineering provenance record, not legal advice, a license grant, or
proof of entitlement. Microsoft proprietary binaries are not covered by the
OpenFetch MIT notice or by third-party open-source source offers.

## Exact conveyed scope

`licenses/microsoft/MICROSOFT-RUNTIME-INVENTORY.json` is authoritative. It
records final path, size, SHA-256, PE file version where available, observed
build-input path and hash, candidate source package, and candidate terms for 52
files:

| Group | Count | Observed immediate source |
|---|---:|---|
| Windows API-set DLLs | 41 | Local Windows Performance Toolkit installation |
| `ucrtbase.dll` | 1 | Local Windows Performance Toolkit installation |
| PySide6-scoped MSVC runtime DLLs | 5 | `PySide6_Essentials-6.11.1-cp39-abi3-win_amd64.whl` |
| Shiboken6-scoped MSVC runtime DLLs | 3 | `shiboken6-6.11.1-cp39-abi3-win_amd64.whl` |
| Root `VCRUNTIME140.dll` and `VCRUNTIME140_1.dll` | 2 | PBS 20250317 stripped runtime asset |

All 52 conveyed bytes match their observed local build inputs. That establishes
which local files PyInstaller selected. It does not show that the local Windows
Performance Toolkit installation is an authorized redistribution package, or
that carriage inside an upstream wheel/runtime grants OpenFetch an
independent right to redistribute each Microsoft file.

## Preserved candidate terms/evidence

| File | Size | SHA-256 | Purpose |
|---|---:|---|---|
| `licenses/microsoft/Visual-Studio-2022-BuildTools-Redist-local.txt` | 187 | `da53b097e02b08e0fc69706102a60bc384fe756426ae4dc4a855e96f95cb2b9c` | Local pointer/evidence; not a complete rights determination |
| `licenses/microsoft/Visual-Studio-2022-REDIST-current.txt` | 62,548 | `e4a51c24c6eb3ba987af353e6ed2676289d3f72372cea08adf1e0de029fd8fb6` | Retained candidate Visual Studio REDIST text |
| `licenses/microsoft/Windows-SDK-10.0.26100.0-license.rtf` | 248,573 | `0f4a26ac9dc50066f8a1bfeaaf3f092d1b9e4791df5487b9f3c31e7c3dc4d7f5` | Installed SDK license evidence |
| `licenses/microsoft/Windows-SDK-10.0.26100.0-third-party-notices.rtf` | 22,279 | `ebb6640a8246b39b70322c5cec9aad7a71e86ea7b86c9c604d3a7f3ff1b30e89` | Installed SDK third-party notices |
| `licenses/microsoft/Windows-Performance-Toolkit-NOTICE.txt` | 198,368 | `b414ddbd1c39786a415caf6c095e78b048465df66f989757de3c0f778628943a` | Installed Toolkit notice evidence |

These files are preserved as found/downloaded evidence. Their presence must not
be described as Microsoft approval, a complete redistributable-file list, or a
transfer of rights.

## Unresolved issues

1. The 42 API-set/UCRT files came from an installed Windows Performance Toolkit
   tree. The exact official installer/package identity and its hash were not
   retained.
2. Some Toolkit files report 10.0.26100.8249 while
   `api-ms-win-core-file-l2-1-0.dll` and `ucrtbase.dll` report 10.0.22000.194.
   The mixed provenance must be reviewed against the exact applicable product
   terms and redistributable list.
3. The PySide6 and Shiboken6 wheels contain their own MSVC runtime copies. The
   wheel source is known, but the downstream redistribution basis has not been
   confirmed.
4. The two root VCRUNTIME files exactly match PBS. PBS provenance does not by
   itself replace confirmation of OpenFetch's distribution rights.
5. No qualified reviewer has approved the exact 52-file list or the intended
   delivery format.

## Required action before PASS

- For every file, identify an official package and the exact license/REDIST
  entry that authorizes the intended Windows distribution, and retain the
  package version, installer/archive hash, and terms in force for that package.
- Prefer building from a documented official redistributable source. If a file
  is expected to be supplied by supported Windows versions, evaluate excluding
  it rather than copying it from an installed toolkit; test the resulting
  application on all supported clean systems.
- Remove duplicate runtime copies only through a reviewed build change followed
  by dependency and smoke testing. Do not delete notices or relabel Microsoft
  files as open source.
- Ship every notice required by the approved Microsoft and upstream-package
  route. Do not make a corresponding-source offer for Microsoft proprietary
  binaries unless the governing terms expressly require/permit such an offer.
- Obtain qualified legal review of the exact binary list and intended public
  distribution method.

Until all items are evidenced, the public-distribution verdict remains
**HOLD**.
