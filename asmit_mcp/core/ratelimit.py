"""Tiny per-host rate limiter for outgoing API calls.

The server has a single local user over stdio, so this is not abuse
protection against the internet — it is a guard against a runaway
client (or a buggy loop) hammering an external API and burning the
shared GitHub 60/hour budget. Limits are deliberately generous: the
full protocol test makes about a dozen external calls, well under
50 per host per minute. When the limit is hit, the call is rejected
with RATE_LIMITED instead of being made.
"""

import threading
import time
from collections import deque

MAX_CALLS_PER_MINUTE_PER_HOST = 50
WINDOW_SECONDS = 60


class RateLimiter:
    def __init__(self, max_calls=MAX_CALLS_PER_MINUTE_PER_HOST,
                 window_seconds=WINDOW_SECONDS):
        self._max_calls = max_calls
        self._window = window_seconds
        self._lock = threading.Lock()
        self._calls = {}

    def allow(self, host):
        now = time.time()
        with self._lock:
            calls = self._calls.setdefault(host, deque())
            while calls and calls[0] <= now - self._window:
                calls.popleft()
            if len(calls) >= self._max_calls:
                return False
            calls.append(now)
            return True


RATE_LIMITER = RateLimiter()
