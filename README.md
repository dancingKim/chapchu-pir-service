# Chapchu policy-isolated PIR service (Dev candidate)

Fork baseline: Apple `pir-service-example` commit
`c4ee8609e614151564fd06d8c6a50d69f85d3fc1`. Dependencies remain pinned by
`Package.resolved`; this fork does not replace the cryptographic implementation.

This implements Guardian #924 U2/U3 server isolation using the existing Apple
PIRClient, PrivacyPass, and homomorphic-encryption libraries. It is **not an
Apple-approved distribution architecture** or evidence of filtering on a device.
The physical probe campaign remains closed. The upstream sample warning below
still applies.

## iOS 26 policy routing

One service/issuer host can serve separate immutable datasets. The bearer token
selects a stable issuer key at `/token-key-for-user-token` and `/issue`. Verified
**full** PrivacyPass key IDs select the same policy for `/config`, `/key`, and
`/queries`. `User-Identifier` is an OS pseudonym used only inside the selected
policy's evaluation-key namespace; it is not the Chapchu account ID or policy.
No requested policy ID, URL, bearer, private key, or request headers are logged.
Policy-mode `/report` rejects requests instead of collecting plaintext URLs.

Each policy has a stable key and a dedicated persistent nonce journal. Replay is
rejected across concurrent requests and service restarts. Keep that journal for
the lifetime of the issuer key. Its file lock permits **one server process**;
replicated deployment requires a shared atomic nonce store and is not implemented.
Corrupt journals or a second writer fail closed. A missing journal is initialized
as new; provisioning/deployment must never delete a journal while reusing its key. The 64 MiB journal bound
fails closed rather than discarding used nonces. Back up the key and journal
together; do not restore an older journal while retaining the key. Never reuse a
policy ID or issuer key for another account/installation.

Policy-specific keys make requests for one policy linkable to each other, and the
public issuer directory exposes the key set. A per-installation policy can have
an anonymity set of one. PIR hides the query contents; it does not remove that
linkability. Apple's permission for per-installation PrivacyPass tiers is still
unconfirmed and must be resolved before distribution.

The current Apple source describes **upcoming iOS 27.3** changes that remove tier
selection and introduce anonymous GET `/config`. These are not restrictions that
already applied to the tested iOS 26 release. This candidate deliberately returns
501 for anonymous `/config` in policy mode and authenticated PIR requests outside
iOS 26. There is no fallback to a global dataset. A supported 27.3 replacement and
any per-profile-host registration rules remain unconfirmed. Existing static
sample configurations retain their previous API/platform behavior.

### Distribution gate and Apple enquiry

Per-installation linkability is a **distribution/activation blocker pending the
privacy model and Apple relay approval**, not a blocker to isolated Dev service
and automated tests. OHTTP does not erase the stable policy-key linkage. Keep
product activation disabled until that question is resolved; do not describe a
working HTTPS endpoint or passing tests as permission to activate NEURLFilter.

Ask Apple:

- May NEURLFilter on iOS 26 use a distinct PrivacyPass issuer key per installation
  at one registered host for an exact custom URL list? Is the resulting policy
  linkage and public key directory compatible with the required privacy model?
- What supported policy-selection mechanism replaces tiers with upcoming 27.3's
  anonymous GET configuration? A single global union changes custom-list verdicts.
- If distinct service hosts are required, does each need separate relay approval,
  or is a documented wildcard registration available?

No enquiry is recorded as sent and no answer is assumed.

## External configuration

Start using `swift run --skip-build PIRService --hostname 127.0.0.1 --port 8080 /absolute/config.json`.
Keep configuration, bearer files, RSA PEM keys, nonce journals, Bloom files, and
processed PIR artifacts outside the repository. Keys/bearers must have no group
or other access (0600 or 0400); journal files are 0600. Do not put token/key values
on command lines. This example contains paths and placeholders only:

```json
{
  "tokens": [],
  "usecases": [],
  "profiles": [{
    "id": "opaque-installation-policy-id",
    "bearerTokenFile": "/run/secrets/policy-bearer",
    "privateKeyFile": "/run/secrets/policy-issuer.pem",
    "nonceFile": "/var/lib/chapchu-pir/policy-redemptions.bin",
    "usecases": [{
      "name": "URL-filter",
      "fileStem": "/var/lib/chapchu-pir/revisions/r1/URL-filter",
      "shardCount": 1,
      "versionCount": 2,
      "revision": "r1",
      "artifactSHA256": "<64 hexadecimal characters>",
      "bloomFile": "/var/lib/chapchu-pir/revisions/r1/bloom.bin",
      "bloomSHA256": "<64 hexadecimal characters>"
    }]
  }]
}
```

The issuer key is an existing RSA private key compatible with upstream
`PrivacyPass.PrivateKey` (2048-bit Blind RSA); it is never generated by policy
configuration loading. Use the same id/key/journal on reload and restart.
Configuration without `profiles` is the original static sample mode. Global
`tokens`, global `usecases`, and `reportDirectory` cannot be combined with profiles.

`artifactSHA256` is SHA256 over ordered artifact files: for each shard from zero,
`<fileStem>-<shard>.params.txtpb`, then `<fileStem>-<shard>.bin`. Prefix **each file**
with its byte length as an unsigned 64-bit big-endian integer. `bloomSHA256` is
ordinary SHA256 of the Bloom file bytes. The trusted rule compiler must produce
both from the same canonical URL revision; digest checking binds the artifact
pair but does not prove the semantic contents of an arbitrary Bloom file.

A configuration ID is length-framed SHA256 over `chapchu-policy-v1`, policy id,
usecase name, revision, and content identity. Content identity is length-framed
SHA256 of the artifact digest, Bloom digest, and upstream PIR config ID. Thus
same-size datasets using identical encryption parameters cannot share a cache
identity. The rule compiler/native integration must also bind its Bloom tag and
applied revision to this artifact pair. Client-side cache reset/refresh, policy
approval, OHTTP transport, entitlement, and Apple registration are separate work.

Stage files under a new immutable revision directory, atomically replace the
external config, then send SIGHUP. All credentials/artifacts are validated before
the policy snapshot changes; failures preserve the previous snapshot. A repeated
revision with different contents is rejected while that revision is retained.
Keep 1–8 server versions (default 2). Queries carrying a retained config ID use
that exact dataset; retired/cross-policy IDs are rejected with 410. Retention is
in memory: a service restart loads the configured current revision and old client
queries receive 410 until refreshed. Stable policy keys do not change when URLs
change. Removing a policy revokes its cached tokens. No removed policy falls back
to the static dataset. Rolling back config must preserve keys/journals and the
chosen immutable revision; do not relabel changed files as an old revision.

## Automated verification

```sh
swift test --disable-automatic-resolution --filter PolicyIsolationTests
swift test --disable-automatic-resolution
```

The outer tests perform real blinded-token issuance and encrypted PIR queries.
They verify two policies with the **same OS identifier and crypto parameters**,
separate evaluation keys and plaintext results, cross-policy config rejection,
old-version retry and retirement, revision collision rejection, concurrent token
replay, full-key-ID tampering, persistent nonce recovery, unsupported API
rejection, and external artifact/Bloom mismatch without replacing working state.
No physical devices, Apple relay, or new filtering observations are involved.

---

# PIR Service Example

[Live Caller ID
Lookup](https://developer.apple.com/documentation/sms_and_call_reporting/getting_up-to-date_calling_and_blocking_information_for_your_app)
is a new feature that allows the system to communicate with a third party service to privately retrieve information
about a phone number for an incoming call. This allows the system to automatically block known spam
callers and display identity information on the incoming call screen.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/apple/pir-service-example/raw/main/Sources/PIRService/PIRService.docc/Resources/overview~dark@2x.png">
  <img alt="Overview of the Live Caller ID Lookup" src="https://github.com/apple/pir-service-example/raw/main/Sources/PIRService/PIRService.docc/Resources/overview@2x.png">
</picture>

[NEURLFilter](https://developer.apple.com/documentation/networkextension/neurlfiltermanager) is a new feature for iOS and macOS that allows the system
to communicate with a third party service to privately check if a requested URL should be allowed or not. This allows your app to implement URL filtering in a privacy preserving manner.
For more information on NEURLFilter, see the [WWDC 2025 talk](https://developer.apple.com/videos/play/wwdc2025/234/).

This repository provides a functional server backend to test the Live Caller ID Lookup and NEURLFilter features.

> [!WARNING]
> While functional, this is just an example service and should not be run in production.

## Overview
PIR Service Example provides:
* [PIRService](https://swiftpackageindex.com/apple/pir-service-example/main/documentation/pirservice), an example service for Live Caller ID Lookup.
* [PrivacyPass](https://swiftpackageindex.com/apple/pir-service-example/main/documentation/privacypass), an implementation of the Privacy Pass publicly verifiable tokens.

The documentation lives at [Swift Package Index](https://swiftpackageindex.com/apple/pir-service-example).

## Developing PIR Service Example
Building PIR Service Example requires:
* 64-bit processor with little-endian memory representation
* macOS or Linux operating system
* [Swift](https://www.swift.org/) version 6.1 or later
* Optionally, [XCode](https://developer.apple.com/xcode/) version 16.3 or later

Additionally, developing PIR Service Example requires:
* [Nick Lockwood SwiftFormat](https://github.com/nicklockwood/SwiftFormat)
* [pre-commit](https://pre-commit.com)
* [SwiftLint](https://github.com/realm/SwiftLint)

### Building
You can build PIR Service Example either via Xcode or via command line in a terminal.
#### Xcode
To build PIR Service Example from Xcode, simply open the root directory (i.e., the `pir-service-example` directory) of the repository in Xcode.
See the [Xcode documentation](https://developer.apple.com/documentation/xcode) for more details on developing with Xcode.

#### Command line
To build PIR Service Example from command line, open the root directory (i.e., the `pir-service-example` directory) of the repository in a terminal, and run
```sh
swift build -c release
```
The build products will be in the `.build/release/` folder.

To build in debug mode, run
```sh
swift build
```
The build products will be in the `.build/debug/` folder.
> [!WARNING]
> Runtimes may be slow in debug mode.

### Testing
Run unit tests via
```sh
swift test -c release --parallel
```
To run tests in debug mode, run
```sh
swift test --parallel
```
> [!WARNING]
> Runtimes may be slow in debug mode.

### Database Reloading
The PIR Service supports dynamic database reloading without requiring a full service restart. This allows you to update the database and configuration while the service continues running.

#### Reloading Process
1. **Update your input database**: Modify your input database file (e.g., `input.txtpb`) with new or updated entries.

2. **Process the new database**: Run `PIRProcessDatabase` to generate the new database files:
   ```sh
   PIRProcessDatabase config.json
   ```

3. **Trigger reload**: Send a `SIGHUP` signal to the running PIR Service process:
   ```sh
   kill -SIGHUP <PID>
   ```

   You can find the process ID using:
   ```sh
   ps aux | grep PIRService
   ```

#### Behavior
- When the service receives a `SIGHUP` signal, it reloads the configuration file and all associated database files.
- The service logs "Reloading configuration..." when starting the reload and "Reloading configuration completed." when finished.
- The service maintains multiple versions of the database to ensure compatibility with clients using older PIR parameters.
- Clients automatically fetch updated PIR parameters periodically, or you can explicitly call `RefreshPIR` to force an immediate update.

#### Version Compatibility
The service is designed to handle database updates gracefully:
- When you update the database, new PIR parameters may be generated.
- The service stores both new and old versions of the dataset.
- Clients using old PIR parameters will continue to work with the previous version of the dataset.
- As clients update their PIR parameters, they will automatically use the new dataset.

For more details on maintaining PIR parameter compatibility across updates, see [Reusing PIR Parameters](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrieval/reusingpirparameters).

### Contributing
If you would like to make a pull request to PIR Service Example, please run `pre-commit install`. Then each commit will run some basic formatting checks.

### Documentation
PIR Service Example uses DocC for documentation.
For more information, refer to [the DocC documentation](https://www.swift.org/documentation/docc) and the [Swift-DocC Plugin](https://swiftlang.github.io/swift-docc-plugin/documentation/swiftdoccplugin).
#### Xcode
The documentation can be built from Xcode via `Product -> Build Documentation`.
#### Command line
The documentation can be built from command line by running
```sh
swift package generate-documentation
```
and previewed by running
```sh
swift package --disable-sandbox preview-documentation --target PIRService
```
