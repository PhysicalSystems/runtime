# Changelog

All notable changes to TinyEdge Runtime are documented here.

## 0.2.0 - Unreleased

- Add neutral physical skill catalog, route request and route decision
  contracts with canonical golden fixtures and JSON Schema projections.
- Add a side-effect-free deterministic resolver that filters exact workcell,
  manifest, state, dependency, calibration, artifact, qualification,
  execution-target and implementation-specific eligibility bindings before
  applying an explicit total-order policy.
- Bind typed skill arguments and fresh precondition assessments to one exact
  invocation, return stable rejection codes, and never grant physical
  execution authority.

## 0.1.0 - 2026-08-31

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
