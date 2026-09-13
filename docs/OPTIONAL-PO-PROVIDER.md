# Optional external PO Token provider

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: HOLD

Audit date: 2026-07-22  
Main application: Neural Extractor V3.0.8  
External helper protocol: `neural-extractor.po-helper` version `1`

Neural Extractor V3.0.8 does not bundle `bgutil-ytdlp-pot-provider` 1.3.1. The
application contains only a first-party adapter for an optional, separately
installed helper process. Normal downloads remain available when the helper is
absent, invalid, incompatible, times out, or is cancelled.

The helper is **not** part of the OpenFetch EXE, release ZIP,
corresponding-source archive, license-text archive, or updater payload. Neural
Extractor must not install, download, repair, update, or activate it silently.
It may provide neutral manual instructions pointing to an independently
maintained official distribution.

The locally audited reference helper is a sibling of, not a child of, the
application project:

| Object | Exact local location | Size / count | SHA-256 |
|---|---|---:|---|
| Helper package root | `D:\Companys\Neuralshield\Software\Neural Extractor\NeuralExtractor PO Helper 1.3.1` | 5,767 files; 169,859,144 bytes | package tree: `441d22abe57eb930b55760711cf4f93e48e82419231f3b9be98c2a6acbf403e5` |
| Activation template, outside package root | `D:\Companys\Neuralshield\Software\Neural Extractor\activation-template.json` | 1,770,046 bytes | `b4eddab32b70f650be1dd4b5d7a59f494bdbc627229705d9e687b24847c75f74` |
| Activation-manifest generator, outside package root | `D:\Companys\Neuralshield\Software\Neural Extractor\NeuralExtractor PO Helper 1.3.1.generate-activation.ps1` | source script | `b0627c1fdaa962d87879f1b39e08697b92626ff15f0b43a1aadbabbfbac0655c` |
| Fixed runtime entrypoint | `<package root>\node.exe` | 85,219,968 bytes | `39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636` |
| Protocol wrapper | `<package root>\helper.mjs` | 9,345 bytes | `29cf6b56be89d3293ccb9af4a557b1c9d8f395216f7b35410ab773bb7a8300a7` |
| Exhaustive npm inventory | `<package root>\npm-dependencies.json` | 112,062 bytes | `eb55b10137a5dd01ced8320148c8e6e57bb871a6738edce2c42b53aa161fd411` |
| Native canvas smoke source | `<package root>\canvas-smoke.mjs` | 1,227 bytes | `7f8326326d26686dbb26e8856a9a73673e4a213a096eb7f0f8dca0c391797aa4` |

These paths identify local audit evidence, not an approved download or public
release. The template is not inside the package closure, so the package hash is
not self-referential. Re-running the external generator produced the same
manifest byte-for-byte and the same tree digest. Any package change requires a
new reviewed manifest and invalidates the values above.

This process boundary materially reduces the main application's bundled GPL and
npm compliance surface. It is an engineering boundary, not a legal conclusion
that the two programs are separate works. That question, and any coordinated
distribution arrangement, requires qualified legal review.

The technical boundary was locally validated, but its legal classification is
unconfirmed. In particular, this document does not conclude that separate
processes necessarily constitute separate works under any applicable law.

## Installation and activation boundary

Installation is an explicit user action:

1. obtain the helper only from the official helper/provider distribution named
   by its maintainer;
2. verify the publisher's version and SHA-256 records;
3. install the complete helper package outside the OpenFetch application
   and source trees; and
4. explicitly place or approve an activation manifest at
   `%LOCALAPPDATA%\OpenFetch\optional-po-provider\active.json` (an existing
   `%LOCALAPPDATA%\NeuralExtractorV3\optional-po-provider\active.json` is copied there on
   first start).

No token, cookie, credential, or content binding belongs in that manifest. The
helper package's own installer, if any, is outside OpenFetch and must be
started deliberately by the user. Removing `active.json` disables the
integration without affecting ordinary downloads.

OpenFetch accepts exactly the following activation-manifest schema
(JSON object; no additional or duplicate keys). This is an abridged shape
example, not an installable manifest: the audited `files` array contains all
5,767 records and must never be shortened in `active.json`.

```json
{
  "schema_version": 1,
  "helper_id": "org.neuralshield.neural-extractor.po-helper",
  "helper_version": "1.0.0",
  "provider_version": "1.3.1",
  "protocol_version": 1,
  "package_root": "C:\\absolute\\path\\outside\\NeuralExtractor",
  "entrypoint": "node.exe",
  "arguments": ["helper.mjs"],
  "package_sha256": "<64 lowercase hexadecimal characters>",
  "files": [
    {
      "path": "node.exe",
      "size": 85219968,
      "sha256": "39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636"
    },
    {
      "path": "helper.mjs",
      "size": 9345,
      "sha256": "29cf6b56be89d3293ccb9af4a557b1c9d8f395216f7b35410ab773bb7a8300a7"
    }
  ]
}
```

`helper_version` is a three-part semantic version. `package_root` must be an
existing absolute directory outside the application root. `entrypoint` and all
`files[].path` values are canonical relative POSIX paths; traversal, drive
prefixes, backslashes, symlinks, and Windows reparse points are rejected. The
entrypoint must be listed in `files`.

The manifest is limited to 8 MiB, 20,000 file records, 40,000 visited package
entries, and 4 GiB of declared package bytes. `entrypoint` must be exactly
`node.exe` and `arguments` must be exactly `["helper.mjs"]`; both files must be
in `files[]`. Arbitrary or runtime-dependent argv is rejected. Every path in
the audited package is printable ASCII; the audited helper rejects a link,
case-fold collision, unsupported entry, or non-ASCII package path while
recomputing its own identity.

The manifest must enumerate every regular file and no extras: relative path,
byte size, and lowercase SHA-256. OpenFetch sorts the entries
case-insensitively and computes `package_sha256` over each record as:

```text
UTF8(path) NUL ASCII(size) NUL ASCII(file_sha256) LF
```

The full package tree, every file hash, and the aggregate package hash are
verified before each process launch. Fixed manifest arguments are limited and
must be non-secret. A mismatch, extra file, missing file, reparse point, version
mismatch, or package located under the application root fails closed.

The activation manifest is a local, explicit trust record and hash closure. It
detects changes after activation; it is not a publisher signature, certificate
chain, or proof of provenance. The user must establish publisher authenticity
before activating it. The verified `package_root` is read-only in practice:
helper logs, caches, generated tokens, sockets, and other runtime state must be
written to a separate user-data directory, because creating or modifying a file
under `package_root` makes the next integrity check fail.

## Process and transport contract

Each operation starts a new manifest-pinned command with `shell=False`, the
verified package root as its working directory, and a reduced environment. No
provider Python module is imported into OpenFetch or its yt-dlp worker;
no JavaScript runtime is loaded into the OpenFetch process; and no Python
object is shared with the helper.

The audited helper command is exactly `node.exe helper.mjs`. Runtime data is not
added to argv. `helper.mjs` computes the complete package digest at startup,
reads one request, and dynamically imports
`./bgutil-ytdlp-pot-provider/server/build/session_manager.js` only for a valid
`generate` action. It constructs `SessionManager(false, {})` inside that Node
process and invokes exactly:

```text
generatePoToken(content_binding, '', bypass_cache, undefined, false,
                undefined, innertube_context)
```

The upstream `poToken` and `expiresAt` fields are normalized to the protocol's
exact `po_token` and integer epoch-seconds-or-`null` response. Upstream console
sinks are suppressed before import because upstream logging can include the
binding or minted token. Proxy, token, authorization, cookie, password, secret,
credential, and API-key environment variables are not used as protocol input;
the application supplies a reduced environment and the helper removes matching
ambient variables before provider code runs. Only the response pipe may carry
the returned token.

The separate package retains the provider's Python modules and complete source
evidence for licensing/provenance, but the helper runtime does not import those
Python files and the main application does not load any file from that package
into its process.

For the bounded provider attempt, OpenFetch disables yt-dlp user-plugin
discovery, clears the PO-provider registries, and registers only its first-party
adapter. The attempt is recognized only with `player_client=mweb`,
`fetch_pot=auto`, `pot_trace=false`, and the adapter's protocol marker set to
`1`. This prevents an installed third-party plugin from being imported as an
accidental fallback.

There is one UTF-8 JSON request on standard input and one UTF-8 JSON response on
standard output per helper process. Standard error must remain empty. Request
and response are each limited to 64 KiB. The request envelope has exactly these
keys:

```json
{
  "protocol": "neural-extractor.po-helper",
  "protocol_version": 1,
  "request_id": "<fresh opaque request id>",
  "action": "hello",
  "payload": {}
}
```

The success response has the matching protocol fields and identity bound to the
verified manifest:

```json
{
  "protocol": "neural-extractor.po-helper",
  "protocol_version": 1,
  "request_id": "<same request id>",
  "helper_id": "org.neuralshield.neural-extractor.po-helper",
  "helper_version": "1.0.0",
  "provider_version": "1.3.1",
  "package_sha256": "<same verified package hash>",
  "ok": true,
  "result": {}
}
```

A failure response replaces `result` with exactly
`"error": {"code": "lowercase_safe_code"}` and sets `ok` to `false`. Neural
Extractor never forwards an external error message because it could echo token
or binding material. The audited helper emits only `invalid_request`,
`unsupported_action`, `generation_failed`, or `response_too_large`; the main
application deliberately maps external generation detail to a generic local
failure.

## Protocol version 1 actions

### `hello`

Request payload: `{}`.

Required result object:

```json
{
  "capabilities": ["mweb.gvs"],
  "provider_version": "1.3.1"
}
```

The result object may not contain other keys; the capability list must contain
`mweb.gvs`. The provider and helper identities, versions, protocol version, and
package hash must match the activation manifest. The total and inactivity
timeout are both 8 seconds.

### `generate`

The request payload has exactly this shape:

```json
{
  "context": "gvs",
  "client_name": "MWEB",
  "content_binding": "<opaque binding>",
  "content_binding_type": "video_id",
  "innertube_context": {
    "client": {
      "clientName": "MWEB",
      "clientVersion": "<version>"
    }
  },
  "authenticated": false,
  "bypass_cache": false
}
```

`content_binding_type` is one of `video_id`, `visitor_data`, `visitor_id`, or
`datasync_id`. `innertube_context` contains only validated fields from this
allowlist: `browserName`, `browserVersion`, `clientFormFactor`, `clientName`,
`clientVersion`, `deviceMake`, `deviceModel`, `gl`, `hl`, `osName`, `osVersion`,
`platform`, `timeZone`, `userAgent`, and `utcOffsetMinutes`. Cookie headers,
authorization headers, browser databases, and arbitrary nested context are not
sent.

The content binding is limited to 16 KiB and may not contain control
characters. A returned token is limited to 32 KiB and must match the protocol's
URL-safe token alphabet.

Required result object:

```json
{
  "po_token": "<opaque token>",
  "expires_at": null
}
```

`expires_at` is either integer Unix epoch seconds or `null`. The total and
inactivity timeout are both 30 seconds.

Content bindings and returned PO tokens exist only in the anonymous pipe and
process memory. They are never placed in command-line arguments, environment
variables, ownership records, or logs. OpenFetch passes a validated
returned token to its in-process first-party yt-dlp adapter; it does not import
the third-party provider. Diagnostics expose only non-sensitive status/error
codes.

Cancellation, timeout, output-limit failure, malformed JSON, identity mismatch,
non-empty stderr, or a nonzero exit code terminates the operation and cleans up
the owned helper process tree. The provider attempt fails closed; ordinary
non-provider behavior remains available.

## Audited helper contents and local validation

The separate reference package contains these audited source/license records:

- the copied provider subtree has 5,751 files; every relative path, size, and
  SHA-256 was compared with the retained V3 vendor evidence, with zero
  mismatches;
- the provider's GPL-3.0-only text is preserved at both `LICENSE` and
  `bgutil-ytdlp-pot-provider/LICENSE`, SHA-256
  `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`;
- the complete upstream 1.3.1 tag archive is retained as
  `source-archives/bgutil-ytdlp-pot-provider-1.3.1-source.zip`, 124,017 bytes,
  SHA-256
  `5df1fa7081ab103209c2394f40ba815a5c8e1b934d6c6fbf80421ca3f2d48471`;
- the actual remediated production npm lock is preserved with SHA-256
  `a1ec8fefee4041a272b783558e1973f1619b0c8ddb24088d2934655ca1111a51`,
  separately from the unmodified upstream lock with SHA-256
  `2a10dfed560ce25c6241b05182e9864b78424f33421ed1c6d2de142fa1ebaedd`;
- `npm-dependencies.json` contains all 184 physical production package records
  (183 unique name/version records), with no undeclared license, null source,
  null integrity, missing physical path, or missing local license path in the
  generated inventory; and
- the complete Node.js 22.17.0 license and embedded notices, provider notices,
  helper README/build/protocol documents, dependency/source inventory, and
  native canvas smoke source are inside the exact package closure.

Three npm notice texts whose registry tarballs do not provide a sufficient
standalone file are explicitly included and bound by the package manifest:

| Dependency | Included text | Exact SHA-256 |
|---|---|---|
| `@bufbuild/protobuf` 2.11.0 | Apache-2.0 text | `c04b4216f1cd4c5a4f7fb2f2a1b0ae70d847e9e0cac7c9dee9bf8cc03177c449` |
| `@bufbuild/protobuf` 2.11.0 | Google varint BSD-3-Clause notice | `0e952cb110ff6944789fbe47c25b38819a3866c04c7c5cbea8d0c0d8f3a92f0e` |
| `saxes` 6.0.0 | upstream composite license text (package metadata: ISC) | `0fac2374380621b22e6b50451057721a9c52935b02d16d106a9f04897f061d0e` |

Their presence does not remove the need to verify whether an Apache upstream
`NOTICE` applies or to disclose modifications where required.

The final local test results were:

| Check | Result |
|---|---|
| Main-client manifest and identity verification | PASS: `available=True`, `integrity_verified=True`, `bundled=False`, helper `1.0.0`, provider `1.3.1`, protocol `1` |
| `hello` through the real main client | PASS: exact envelope/package identity and empty stderr |
| Complete manifest regeneration | PASS: 5,767 files, 169,859,144 bytes, deterministic manifest and tree digest |
| Real `canvas.node` native load/draw/PNG | PASS: pixel `[18,52,86,255]`, 95-byte valid PNG, empty stderr |
| Provider JavaScript load | PASS: `SessionManager` imported and constructed and `generatePoToken` was callable inside the external Node process |
| Invalid `generate` privacy test | PASS: safe `invalid_request`, empty stderr, supplied binding marker not echoed |
| Live network PO-token mint | **NOT RUN**: prohibited by the no-network audit constraint |

These checks establish local protocol, process, integrity, loader, and privacy
behavior. They do not prove that a live upstream token can currently be minted,
that future upstream behavior will remain compatible, or that distribution is
legally compliant.

## Helper distribution obligations

**Public distribution of the helper package remains HOLD.** The local package
is a technical reference and audit object, not an approved public helper
release. `canvas` 3.2.1 contributes `canvas.node` and 44 native DLLs which were
mapped to 34 exact historical MSYS2 UCRT64 packages. `librsvg-2-2.dll` also
contains a Rust dependency closure for which only a minimum detectable set was
recovered. The package does not yet accompany all exact MSYS2 source archives,
native license directories and notices, original native build environment,
complete librsvg/Rust crate sources and checksums, modification/build records,
or practical LGPL replacement/relink/install instructions. The missing live
token-mint test is a separate functional verification gap.

The helper's `DEPENDENCY-SOURCE.md` identifies the exact known package versions
and source locations, but URLs alone are not treated as conveyed source or as a
valid source offer. Qualified legal review must determine the applicable GPL,
LGPL, exception, dual-license, notice, source-delivery, and installation
requirements before anyone distributes the helper.

The external helper has its own, independent distribution closure. Whoever
distributes it must audit and accompany it with, as applicable:

- the helper executable/wrapper and its source;
- the wrapper's declared GPL-3.0-only terms and a confirmed, non-invented
  copyright holder/year notice before public distribution;
- the exact `bgutil-ytdlp-pot-provider` 1.3.1 Python and JavaScript/TypeScript
  sources it uses;
- the provider's unmodified GPLv3 license and all copyright notices;
- the exact Node/runtime files, npm packages, native modules such as `canvas`,
  and every transitive native dependency actually shipped;
- every dependency license, attribution, NOTICE file, source location, and
  redistribution condition;
- complete corresponding source for GPL-covered object code, including build
  scripts, patches, generated-source inputs, package locks, and source hashes;
- a valid written source offer if that distributor chooses an offer instead of
  directly accompanying source, with duration and scope checked for the release
  medium; and
- helper-specific archive scans and runtime smokes, including an actual
  `canvas.node`/native-library test when canvas is present; and
- a live, non-secret token-mint compatibility test performed in an authorized
  network environment without placing a binding, token, cookie, or credential
  in argv, environment variables, stderr, or logs.

Those materials belong to the helper distribution, not the OpenFetch
release. OpenFetch must not copy the helper, its provider sources, npm
tree, native binaries, license bundle, or source offer into its EXE, release
ZIP, source archive, updater, cache, or installer.

## Why this simplifies the main distribution

Keeping the provider external and optional removes its GPLv3 Python modules,
GPLv3 JavaScript output, Node package tree, canvas native closure, and conflicting
libffi from the main PyInstaller archive. It also changes the integration from
in-process third-party imports to a bounded, versioned process protocol. That
materially simplifies the main artifact's dependency inventory, license bundle,
source archive, native-loader behavior, and update path.

It does not eliminate all compliance questions. A reviewer must still assess
the first-party adapter, the practical independence of the helper, how the two
are marketed and obtained, and whether any distributor offers them together.
No statement in this document should be read as legal certainty or as changing
the provider's license.

## Current verdict

- **Local optional-helper architecture: technical PASS.** The audited package
  is external, manually activated, version- and hash-pinned, process-separated,
  absent-safe, and accepted by the real main client. This is not a live token
  functionality PASS because no authorized network mint was run.
- **Public helper distribution: HOLD.** Canvas/MSYS2 native source, notices and
  relink material; the complete librsvg/Rust closure; exact ownership notice;
  live token-mint verification; and qualified legal review remain open.
- **Neural Extractor V3.0.8 public distribution: HOLD.** Keeping the helper out
  of the EXE/release/updater removes this helper's payload from the main binary
  audit, but it does not override the independent application release gate or
  approve coordinated distribution of both products.

These are engineering verdicts for the audited local files. They are not legal
advice, a source offer, or a statement of legal certainty.
