"""secretsync — declarative secret sealing & sync for GitOps. Part of the Cognis Neural Suite."""

from secretsync.core import (
    TOOL_NAME,
    TOOL_VERSION,
    SealKey,
    SecretSyncError,
    audit_secret_names,
    generate_key,
    load_json,
    load_key,
    merge_sealed,
    peek,
    rotate,
    seal_bytes,
    seal_file,
    seal_secret,
    seal_values,
    unseal_bytes,
    unseal_secret,
    verify_sealed,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME", "TOOL_VERSION", "__version__", "SealKey", "SecretSyncError",
    "audit_secret_names", "generate_key", "load_json", "load_key",
    "merge_sealed", "peek", "rotate", "seal_bytes", "seal_file", "seal_secret",
    "seal_values", "unseal_bytes", "unseal_secret", "verify_sealed",
]
