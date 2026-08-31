# Changelog

All notable changes to TinyEdge Runtime are documented here.

## 0.1.0 - Unreleased

- Extract the stdlib-only Runtime v1 kernel from `tinyedge-agent`.
- Publish six strict wire contracts and their golden fixtures.
- Add side-effect-free qualified-bundle resolution.
- Add deterministic synchronous execution with fail-closed cleanup.
- Add device-free fakes and contract conformance validation.
- Add neutral physical manifest, sequential protocol and terminal run-record
  contracts with side-effect-free compatibility resolution.
- Keep command acknowledgement, independent observed evidence and safe-stop
  cleanup distinct in physical run records.
- Bind observer independence to explicit trust domains and retain failed
  preconditions without dispatching the protected command.
