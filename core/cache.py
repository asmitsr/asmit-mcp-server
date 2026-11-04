"""Tiny in-memory TTL cache (process-local, never written to disk).

Used for currency rates only: rates change slowly, so a 5-minute cache
stops repeated conversions from hammering the rate API. GitHub data is
deliberately NOT cached here — repository health should stay fresh.
"""

import time

DEFAULT_TTL_SECONDS = 300


class TTLCache:
    def __init__(self, ttl_seconds=DEFAULT_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._store = {}

    def get(self, key):
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key, value):
        self._store[key] = (value, time.time() + self._ttl)


CURRENCY_CACHE = TTLCache()
