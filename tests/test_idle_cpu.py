#!/usr/bin/env python3
"""Verify an idle multi-worker proxy does not spin its epoll loop."""

import os
import time

import requests


host = os.environ.get("TELEPROXY_HOST", "teleproxy")
stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
url = f"http://{host}:{stats_port}/stats"


def epoll_calls():
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    for line in response.text.splitlines():
        if line.startswith("epoll_calls\t"):
            return int(line.split("\t", 1)[1])
    raise AssertionError("epoll_calls missing from /stats")


before = epoll_calls()
time.sleep(2)
after = epoll_calls()
delta = after - before

assert delta < 100, f"idle proxy made {delta} epoll calls in 2 seconds"
print(f"Idle epoll rate passed: {delta} calls in 2 seconds")
