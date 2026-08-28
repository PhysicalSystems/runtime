"""TinyEdge Runtime v1 contracts and deterministic local execution kernel."""

__version__ = "0.1.0"

from .contracts import (
    ActionChunk,
    AdapterCapability,
    ArtifactRef,
    BundleCapability,
    ObservationEnvelope,
    RuntimeCapabilities,
    RuntimeContractError,
    RuntimePlan,
    RuntimeTelemetrySummary,
    SafetyPolicy,
    TargetLock,
    seal_runtime_capabilities,
    seal_runtime_plan,
)
from .registry import (
    BUNDLE_VERSION,
    QualifiedBundle,
    ResolvedRuntime,
    RuntimeCompatibilityError,
    RuntimeRegistry,
)
from .session import (
    RuntimeCleanupError,
    RuntimeExecutionError,
    RuntimeSession,
    RuntimeState,
)

__all__ = [
    "__version__",
    "ActionChunk",
    "AdapterCapability",
    "ArtifactRef",
    "BundleCapability",
    "BUNDLE_VERSION",
    "ObservationEnvelope",
    "QualifiedBundle",
    "ResolvedRuntime",
    "RuntimeCapabilities",
    "RuntimeCleanupError",
    "RuntimeCompatibilityError",
    "RuntimeContractError",
    "RuntimeExecutionError",
    "RuntimePlan",
    "RuntimeRegistry",
    "RuntimeSession",
    "RuntimeState",
    "RuntimeTelemetrySummary",
    "SafetyPolicy",
    "TargetLock",
    "seal_runtime_capabilities",
    "seal_runtime_plan",
]
