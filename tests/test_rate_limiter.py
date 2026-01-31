"""Tests for the token-bucket rate limiter."""

import time
import pytest

from basemesh.rate_limiter import RateLimiter, _TokenBucket


class TestTokenBucket:
    def test_initial_tokens(self):
        bucket = _TokenBucket(max_tokens=3, refill_rate=1.0)
        assert bucket.tokens == 3.0

    def test_consume(self):
        bucket = _TokenBucket(max_tokens=3, refill_rate=0.0)
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_refill(self):
        bucket = _TokenBucket(max_tokens=3, refill_rate=100.0)
        bucket.consume()
        bucket.consume()
        bucket.consume()
        # Force some time to pass for refill
        bucket.last_refill = time.time() - 1.0
        assert bucket.consume() is True

    def test_max_cap(self):
        bucket = _TokenBucket(max_tokens=3, refill_rate=1000.0)
        bucket.last_refill = time.time() - 100
        bucket.consume()
        assert bucket.tokens <= 3.0


class TestRateLimiter:
    def test_burst_allowed(self):
        rl = RateLimiter(max_per_minute=10.0, burst=3)
        assert rl.is_allowed("node1") is True
        assert rl.is_allowed("node1") is True
        assert rl.is_allowed("node1") is True

    def test_burst_exceeded(self):
        rl = RateLimiter(max_per_minute=10.0, burst=2)
        assert rl.is_allowed("node1") is True
        assert rl.is_allowed("node1") is True
        assert rl.is_allowed("node1") is False

    def test_independent_senders(self):
        rl = RateLimiter(max_per_minute=10.0, burst=1)
        assert rl.is_allowed("node1") is True
        assert rl.is_allowed("node2") is True
        assert rl.is_allowed("node1") is False
        assert rl.is_allowed("node2") is False

    def test_cleanup_stale(self):
        rl = RateLimiter(max_per_minute=10.0, burst=3)
        rl.is_allowed("node1")
        rl.is_allowed("node2")
        # Make node1 stale
        rl._buckets["node1"].last_refill = time.time() - 700
        removed = rl.cleanup_stale(max_age=600)
        assert removed == 1
        assert "node1" not in rl._buckets
        assert "node2" in rl._buckets

    def test_refill_over_time(self):
        rl = RateLimiter(max_per_minute=600.0, burst=1)  # 10/sec
        assert rl.is_allowed("node1") is True
        assert rl.is_allowed("node1") is False
        rl._buckets["node1"].last_refill = time.time() - 1.0
        assert rl.is_allowed("node1") is True

    def test_zero_burst(self):
        rl = RateLimiter(max_per_minute=10.0, burst=0)
        # With 0 burst, nothing is initially allowed
        assert rl.is_allowed("node1") is False

    def test_new_sender_gets_burst(self):
        rl = RateLimiter(max_per_minute=10.0, burst=5)
        # First 5 requests should all succeed
        for _ in range(5):
            assert rl.is_allowed("newnode") is True
        assert rl.is_allowed("newnode") is False

    def test_cleanup_no_stale(self):
        rl = RateLimiter(max_per_minute=10.0, burst=3)
        rl.is_allowed("node1")
        removed = rl.cleanup_stale()
        assert removed == 0

    def test_multiple_stale(self):
        rl = RateLimiter(max_per_minute=10.0, burst=3)
        rl.is_allowed("a")
        rl.is_allowed("b")
        rl.is_allowed("c")
        for sid in rl._buckets:
            rl._buckets[sid].last_refill = time.time() - 700
        removed = rl.cleanup_stale(max_age=600)
        assert removed == 3
