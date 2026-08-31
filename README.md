# TinyEdge Runtime

TinyEdge Runtime is the open-source execution kernel and strategy SDK for
running model-driven workloads on edge devices and robots. It provides strict,
versioned contracts; side-effect-free compatibility resolution; and a
deterministic fail-closed lifecycle without owning fleet credentials, hardware
drivers, benchmark campaigns, or cloud orchestration.

Runtime v1 currently implements the synchronous `local_sync_v1` strategy. It
is intentionally small, standard-library-only, and device-free. Concrete
sensor, model, robot, and transport integrations live in host applications or
separate adapter packages.

Runtime also defines neutral physical-system manifest, sequential protocol and
terminal run-record contracts. They let an Agent bind typed, unit-bounded
commands to calibrated devices and commissioned artifacts, then keep command
acknowledgement separate from fresh, independent-trust-domain observations and
explicit safe-stop results. Failed preconditions can be retained without ever
dispatching the protected command. This imports no vendor framework and grants
no execution authority. See
[`docs/runtime-v1.md`](docs/runtime-v1.md#physical-workflow-contracts).

## Install

The first packaged release is being prepared. From a checkout:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

The distribution name is `tinyedge-runtime`; the Python import is
`tinyedge_runtime`.

## Minimal example

```python
from tinyedge_runtime import RuntimeRegistry, RuntimeSession

registry = RuntimeRegistry()
registry.register_sensor(sensor)
registry.register_model(model)
registry.register_robot(robot)
registry.register_bundle(qualified_bundle)

resolved = registry.resolve(sealed_plan, capabilities)
with RuntimeSession(resolved, monotonic_clock) as session:
    session.prepare()
    session.arm()
    action = session.step()
```

Resolution is side-effect free. Adapter resources are opened only by
`prepare()`. If a guarded operation fails after resource acquisition, the
session fences output, attempts `safe_stop` at most once, closes every opened
resource in reverse order, and preserves the primary failure.

## Repository map

- `src/tinyedge_runtime/`: contracts, registry, execution session and test fakes.
- `fixtures/`: canonical Runtime v1 golden contract values.
- `schemas/`: public JSON Schema projections of the wire contracts.
- `tests/`: deterministic contract, compatibility and lifecycle tests.
- `docs/runtime-v1.md`: normative Runtime v1 behavior and non-goals.
- `BOUNDARY.md`: ownership across Runtime, Agent, Platform and Benchmarks.

Validate one or more contract documents with:

```powershell
tinyedge-runtime-validate fixtures/runtime-plan-v1.json
```

Physical protocol resolution is also non-actuating:

```python
from tinyedge_runtime import resolve_physical_protocol

resolved = resolve_physical_protocol(manifest, protocol)
assert resolved.physical_execution_authorized is False
```

## Safety and evidence boundary

Runtime can prove that its Python contracts and tested lifecycle behaved as
specified. It cannot, by itself, prove physical robot safety, controller
acknowledgement, model quality, deadline performance, artifact authenticity, or
benchmark success. Those claims require separately qualified adapters,
hardware and evidence.

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability and
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

## License

TinyEdge Runtime is licensed under the [Apache License 2.0](LICENSE).
