# Contributing to GRYM

Thank you for taking the time to contribute. We are building a fast, scope-obsessed, Rust-native security assessment toolkit, and we would rather have one careful patch than ten reckless ones.

If you are reading this because you want to add a cool scanner that "just sends a quick payload": close your laptop, take a walk, and then come back and read the whole file.

## The one rule to rule them all

Every outbound action must go through `grym_core::ScopedClient` or an equivalent scope-enforcing transport. Do not add raw `reqwest`, `TcpStream`, or browser clients to module crates. If you find a way to bypass the scope guard, treat it as a bug, not a feature, and open an issue immediately.

## What we need

- Deterministic tests for every scope decision path. A regression that silently expands scope is a release blocker.
- New detection techniques should be non-destructive by default. Higher-risk validation belongs behind the explicit technique-tier and attestation APIs.
- Mapping packs and templates are versioned data. Never hardcode a taxonomy category solely in scanner logic.
- Evidence must be redacted before persisting or reporting it.
- Clear documentation and module boundaries. Keep the foundation safe and put optional, risky features behind separate crates.

## What we do not need

- Pre-packaged remote exploits that run automatically.
- Scanners that bypass scope, rate limits, or circuit breakers.
- Hardcoded credentials, API keys, or personal data in fixtures.
- Pull requests that change the safety model without a design discussion first.

## Getting started

1. Fork the repository and clone your fork.
2. Install Rust 1.94 or later. The workspace uses `rust-toolchain.toml` to pin the toolchain.
3. Run the quality gates to make sure everything starts green:

   ```bash
   cargo fmt --check
   cargo clippy --workspace --all-targets
   cargo test --workspace
   cargo xtask mapping-check
   ```

4. Make your changes, add tests, and run the gates again.

## Code style

- `cargo fmt` is the source of truth.
- `unsafe` is forbidden in the workspace.
- `unwrap`, `expect`, `panic`, `todo`, and `unimplemented` are denied by clippy. Use proper error propagation.
- Keep functions small and module boundaries explicit.
- Document public APIs with doc comments.

## Adding a new web scanner module

1. Create a new module under `crates/grym-web-scanner/src/`, e.g. `my_check.rs`.
2. Use `grym_core::ScopedClient` for any outbound request.
3. Return `Vec<Finding>` with severity, confidence, and a redacted evidence summary.
4. Add a `check_*` function and wire it into `scan_all_vulns` in `lib.rs`.
5. Add unit tests with a mock or a local fixture. See `tests/fixtures/` for intentionally vulnerable definitions.
6. Run `cargo test -p grym-web-scanner`.

## Adding a new CVE or template

1. Add the entry to the appropriate JSON / YAML mapping pack.
2. Include a deterministic signature, affected versions, remediation, and a safe response-only detection pattern.
3. Run `cargo xtask mapping-check` to validate versioning and taxonomy references.
4. Do not add executable exploit code to the mapping pack.

## Testing

- Unit tests live in the crate they test.
- Integration tests live in `tests/`.
- Use the local fixtures and the `grym serve` API for end-to-end browser extension tests.
- A red build is a red build. We do not merge on a prayer.

## Commit messages

Write concise, descriptive commits in the imperative mood:

```
Add JWT configuration scanner
Fix scope guard redirect re-authorization
```

## Questions?

Open an issue with the `question` label. If you are unsure whether your change is safe, ask before you code. We would rather talk early than revert later.

## Code of conduct

Be professional, patient, and excellent to each other. Assume good intent, but also assume the scope guard is watching.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
