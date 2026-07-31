#!/usr/bin/env python3
"""Keep compare-and-swap operations on the portable atomic builtins."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
offenders = []
for path in (ROOT / "src").rglob("*.[ch]"):
    if "__sync_bool_compare_and_swap" in path.read_text():
        offenders.append(str(path.relative_to(ROOT)))

assert not offenders, (
    "__sync_bool_compare_and_swap remains in: " + ", ".join(offenders)
)
assert "-latomic" in (ROOT / "Makefile").read_text(), (
    "Linux builds must link libatomic for non-lock-free ARM64 operations"
)
assert "openssl zlib libatomic iproute2" in (ROOT / "Dockerfile").read_text(), (
    "The runtime image must provide libatomic for ARM64"
)
for name in (
    "Dockerfile.check",
    "Dockerfile.junk",
    "Dockerfile.link",
    "Dockerfile.tracked-ips-cap",
):
    assert "libatomic" in (ROOT / "tests" / name).read_text(), (
        f"tests/{name} must provide libatomic for ARM64"
    )
print("Atomic portability checks passed")
