#!/usr/bin/env python3
"""Check direct E2E transport helpers keep their three-value contract."""

import ast
import importlib.util
import os
from pathlib import Path
from unittest.mock import patch


path = Path(__file__).with_name("test_direct_e2e.py")
tree = ast.parse(path.read_text())

for node in tree.body:
    if not isinstance(node, ast.AsyncFunctionDef):
        continue
    if node.name not in {"test_obfs2_all", "test_faketls_all"}:
        continue
    for child in ast.walk(node):
        if not isinstance(child, ast.Return) or child.value is None:
            continue
        assert isinstance(child.value, ast.Tuple) and len(child.value.elts) == 3, (
            f"{node.name} return on line {child.lineno} must contain three values"
        )

print("Direct E2E transport contracts passed")

spec = importlib.util.spec_from_file_location("direct_e2e_contract_target", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

auth_attempts = []


async def fake_obfs2(*args, bot_token="", session_str="", **kwargs):
    auth_attempts.append((bot_token, session_str))
    if session_str:
        raise module.SessionUnauthorized
    return True, {"1mb": 1.0}, 1.0


async def fake_faketls(*args, bot_token="", session_str="", **kwargs):
    auth_attempts.append((bot_token, session_str))
    return True, {"1mb": 1.0}, 1.0


env = {
    "TG_TEST_SESSION": "stale-test-session",
    "TG_BOT_TOKEN": "fallback-bot-token",
    "TELEPROXY_SECRET": "0123456789abcdef0123456789abcdef",
}
with (
    patch.dict(os.environ, env, clear=True),
    patch.object(module, "_patch_mtproxy_test_dc"),
    patch.object(module, "_unpatch_mtproxy_test_dc") as unpatch_test_dc,
    patch.object(module, "test_obfs2_all", fake_obfs2),
    patch.object(module, "test_faketls_all", fake_faketls),
    patch.object(module, "_check_drs_delay_stats", return_value=True),
    patch.object(module, "_check_proxy_stats", return_value=(True, {})),
):
    try:
        module.main()
    except SystemExit as exc:
        assert exc.code == 0, f"bot fallback exited with {exc.code}"

unpatch_test_dc.assert_called_once_with()
assert auth_attempts == [
    ("", "stale-test-session"),
    ("fallback-bot-token", ""),
    ("fallback-bot-token", ""),
]
print("Direct E2E bot fallback passed")
