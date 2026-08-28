# TinyEdge Runtime v1

## Status and scope

Runtime v1 is the smallest trustworthy local execution kernel for one sensor,
one model and one robot adapter using the synchronous `local_sync_v1` strategy.
It defines immutable wire contracts, exact bundle resolution, deterministic
resource ownership, output fencing and bounded telemetry.

Runtime v1 is deliberately not a device daemon, artifact downloader, network
transport, optimizer, benchmark runner or physical safety certification. Host
applications provide concrete adapters and establish the trust of plans,
capabilities and artifacts before calling Runtime.

## Design principles

1. Compatibility resolution is exact and has no adapter side effects.
2. Resource ownership begins at `RuntimeSession.prepare()`.
3. Invalid, stale, replayed or mismatched data never reaches robot output.
4. A guarded failure fences output before cleanup.
5. Safe-stop is attempted at most once and cleanup never masks the primary
   failure.
6. Wire-contract meanings are versioned; v1 rejects unknown fields.
7. Runtime emits bounded primitive facts rather than benchmark conclusions.

## Contracts

| Contract | Version | Meaning |
|---|---|---|
| Capability snapshot | `tinyedge-runtime-capabilities-v1` | Exact device/environment, adapter attestations and qualified bundle digests |
| Qualified bundle | `tinyedge-runtime-qualified-bundle-v1` | One predeclared internally compatible sensor/model/robot composition |
| Runtime plan | `tinyedge-runtime-plan-v1` | Target lock, bundle, strategy, schemas, artifacts and local safety policy |
| Observation | `tinyedge-observation-v1` | Source identity, order, monotonic capture/receipt times and finite vectors |
| Action chunk | `tinyedge-action-chunk-v1` | Source observation, ordered axes/units, validity horizon, model digest and finite actions |
| Telemetry summary | `tinyedge-runtime-telemetry-v1` | Bounded lifecycle, rejection, timing, safe-stop and cleanup facts |

The strict Python definitions live in
[`contracts/models.py`](../src/tinyedge_runtime/contracts/models.py) and the
qualified bundle in [`registry.py`](../src/tinyedge_runtime/registry.py).
Canonical examples are checked into [`fixtures/`](../fixtures/).

### Canonical hashing

Runtime v1 canonical JSON:

- recursively sorts object keys;
- preserves array order;
- uses compact UTF-8 JSON;
- normalizes an integral float such as `1.0` to `1`;
- rejects NaN and infinity.

Self-hashing contracts omit their own top-level hash field before hashing and
format the SHA-256 result as `sha256:<64 lowercase hex>`. These bytes are API.
Changing the rules requires a new contract version and new golden fixtures.

### Exact ordered actions

Action width alone is insufficient. A plan, bundle and action must agree on the
exact ordered axis and unit tuples. Runtime never guesses, reorders or converts
values. It also checks finite values, declared limits, model artifact identity,
observation identity, clock domain and validity times before output.

The v1 `committed_prefix` field describes the prefix inside one action chunk.
It does not define cross-chunk replacement, overlap or asynchronous queue
ownership. Those semantics require a separately versioned strategy contract.

## Resolution

`RuntimeRegistry.resolve(plan, capabilities)`:

1. verifies the target device, environment and capability digest;
2. selects the exact registered bundle and matches its attested digest;
3. requires the exact supported strategy, clock and schemas;
4. requires identical ordered axes, units and artifact tuples;
5. rejects a plan that widens the bundle's qualified safety envelope;
6. verifies adapter identities and lifecycle methods have not changed;
7. verifies the model adapter binds the qualified model artifact;
8. returns a protected `ResolvedRuntime` value.

Resolution never calls adapter `open`, `read`, `predict`, `arm`,
`apply_chunk`, `safe_stop` or `close` methods. `ResolvedRuntime` values cannot
be constructed outside registry resolution.

## Session lifecycle

```text
VALIDATED -> PREPARED -> ARMED -> RUNNING
                              -> SAFE_STOPPED (only when safe_stop returns)
                              -> CLOSED
```

`prepare()` opens sensor, model and robot adapters in that order. Each closer is
registered before the corresponding open call so partial acquisition is still
cleaned up. `arm()` arms the robot only after all adapters have opened.

`step()` checks cancellation around sensor read, inference, final validation
and output. It rejects observation replay, non-increasing sequence or capture
time, future or stale observations, and actions that do not bind the current
observation and plan. Observation freshness is checked before inference and
again at the output boundary.

On a guarded failure after acquisition, the session:

1. fences all further output;
2. attempts robot `safe_stop` at most once if the robot was opened;
3. closes successfully opened resources in reverse order;
4. records bounded cleanup reason codes;
5. re-raises the primary failure.

A normal `close()` follows the same stop and reverse-close path. It is
idempotent. When only cleanup fails, `RuntimeCleanupError` is raised after all
cleanup attempts finish.

## Adapter protocols

Runtime uses structural Python protocols for sensors, models, robots,
monotonic clocks and cancellation tokens. Host applications own the concrete
implementations and their qualification. Runtime does not dynamically import
adapter names from a plan; a host must register explicit objects and explicit
qualified bundles.

The device-free fakes under
[`testing/`](../src/tinyedge_runtime/testing/) support deterministic contract
and lifecycle tests. Passing fake tests is not evidence of hardware behavior.

## Telemetry and evidence

`RuntimeTelemetrySummary` contains plan-bound state and bounded counters,
latest timing values, stop confirmation and cleanup reason codes. It excludes
observations, action payloads, secrets and arbitrary exception messages.

`safe_stop_confirmed=true` means only that the adapter's Python `safe_stop`
method returned. It does not prove controller acknowledgement, motor state,
watchdog health or physical safety.

SHA-256 equality is tamper evidence, not authentication. A production host must
authenticate job intent, authorize and verify artifact bytes, establish current
capabilities, and qualify concrete adapters independently.

## Versioning and future strategies

Runtime v1 supports only `local_sync_v1`. Multimodal tensor observations,
asynchronous chunk scheduling, correction, transport envelopes, raw event
ledgers and physical adapters are future additive work. They must not silently
reinterpret a v1 field.

The intended asynchronous design will use absolute control steps,
controller-owned committed ranges, refill at or below a queue watermark,
explicit deadlines and late-result classifications, cancellation/reconnect
semantics and an explicit underflow policy. Those requirements will land as new
versioned contracts with deterministic delay/loss/reorder conformance tests.
