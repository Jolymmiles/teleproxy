#!/usr/bin/env python3
"""E2E tests for Teleproxy multi-secret support.

Verifies that the proxy accepts fake-TLS handshakes using each of
multiple configured secrets, and still rejects unknown secrets.
"""
import os
import sys
import time
import urllib.request

from test_tls_ja4 import compute_ja4
from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    build_client_hello,
    wait_for_proxy,
)


def test_multi_secret_handshake():
    """Verify fake-TLS handshake succeeds with each configured secret."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")

    assert secrets_csv, "TELEPROXY_SECRETS environment variable not set"
    secrets = [s.strip() for s in secrets_csv.split(",") if s.strip()]
    assert len(secrets) >= 2, f"Expected at least 2 secrets, got {len(secrets)}"

    for i, secret_hex in enumerate(secrets):
        secret_bytes = bytes.fromhex(secret_hex)
        first_alpn = "h2" if i == 0 else "h3"
        data, client_random = _do_handshake(
            host, port, secret_bytes, first_alpn=first_alpn
        )

        assert len(data) >= 138, (
            f"Secret #{i+1} ({secret_hex[:8]}...): Response too short "
            f"({len(data)} bytes)"
        )
        assert _verify_server_hmac(data, client_random, secret_bytes), (
            f"Secret #{i+1} ({secret_hex[:8]}...): HMAC mismatch"
        )
        print(f"  Secret #{i+1} ({secret_hex[:8]}...): handshake OK")


def test_per_secret_ja4_buckets():
    """Verify distinct ClientHellos stay in their matching secret buckets."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    domain = os.environ.get("EE_DOMAIN", "172.30.0.10")
    expected = {
        "alpha": compute_ja4(build_client_hello(domain, first_alpn="h2")),
        "beta": compute_ja4(build_client_hello(domain, first_alpn="h3")),
    }

    time.sleep(0.5)
    stats = urllib.request.urlopen(
        f"http://{host}:{stats_port}/stats", timeout=5
    ).read().decode()
    metrics = urllib.request.urlopen(
        f"http://{host}:{stats_port}/metrics", timeout=5
    ).read().decode()

    for label, ja4_hash in expected.items():
        stats_line = f"secret_{label}_ja4_seen\t{ja4_hash}\t"
        metric = f'teleproxy_secret_ja4_seen{{secret="{label}",hash="{ja4_hash}"}}'
        assert stats_line in stats, f"missing {stats_line!r} in /stats"
        assert metric in metrics, f"missing {metric!r} in /metrics"

    assert (
        f'secret="alpha",hash="{expected["beta"]}"' not in metrics
    ), "beta JA4 leaked into alpha bucket"
    assert (
        f'secret="beta",hash="{expected["alpha"]}"' not in metrics
    ), "alpha JA4 leaked into beta bucket"


def test_wrong_secret_still_rejected():
    """Verify that an unknown secret is rejected with multiple secrets configured."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")

    assert secrets_csv, "TELEPROXY_SECRETS environment variable not set"
    first_secret = secrets_csv.split(",")[0].strip()

    # Flip all bits to get an unknown secret
    wrong_secret = bytes(b ^ 0xFF for b in bytes.fromhex(first_secret))

    data, client_random = _do_handshake(host, port, wrong_secret)
    assert len(data) >= 10, "No response for wrong secret"
    assert not _verify_server_hmac(data, client_random, wrong_secret), (
        "HMAC matched with wrong secret — should have been rejected"
    )
    print("  Wrong secret correctly rejected with multi-secret config")


def main():
    tests = [
        ("test_multi_secret_handshake", test_multi_secret_handshake),
        ("test_per_secret_ja4_buckets", test_per_secret_ja4_buckets),
        ("test_wrong_secret_still_rejected", test_wrong_secret_still_rejected),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting multi-secret TLS tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    passed = 0
    failed = 0
    errors = []

    for name, fn in tests:
        try:
            print(f"[RUN]  {name}")
            fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
