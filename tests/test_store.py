"""Tests for the IntentStore persistence module."""

import json
import os
import stat
import time

import pytest

from basemesh.store import Intent, IntentStatus, IntentStore, QUEUE_FILENAME


@pytest.fixture
def tmp_queue_dir(tmp_path):
    d = tmp_path / "basemesh"
    d.mkdir()
    return d


@pytest.fixture
def store(tmp_queue_dir):
    return IntentStore(queue_dir=tmp_queue_dir)


class TestAddIntent:
    def test_add_and_reload(self, store, tmp_queue_dir):
        intent = store.add(
            mode=3, wallet_name="alice", recipient="0xAbAb" * 5,
            amount=0.5, token_decimals=18,
        )
        assert intent.status == IntentStatus.PENDING
        assert intent.mode == 3
        assert intent.wallet_name == "alice"
        assert intent.amount == 0.5

        # Reload from disk
        store2 = IntentStore(queue_dir=tmp_queue_dir)
        reloaded = store2.get(intent.id)
        assert reloaded is not None
        assert reloaded.wallet_name == "alice"
        assert reloaded.amount == 0.5

    def test_add_mode1(self, store):
        intent = store.add(
            mode=1, wallet_name="bob", recipient="0xCdCd" * 5,
            amount=1.0,
        )
        assert intent.mode == 1

    def test_add_invalid_mode(self, store):
        with pytest.raises(ValueError, match="mode must be 1 or 3"):
            store.add(mode=2, wallet_name="x", recipient="0x" + "ab" * 20, amount=1.0)

    def test_add_with_token(self, store):
        intent = store.add(
            mode=3, wallet_name="alice", recipient="0xAbAb" * 5,
            amount=10.0, token_address="0x1234" * 5, token_decimals=6,
        )
        assert intent.token_address == "0x1234" * 5
        assert intent.token_decimals == 6


class TestDuplicateRejection:
    def test_duplicate_pending_rejected(self, store):
        store.add(mode=3, wallet_name="alice", recipient="0xAbAb" * 5, amount=0.5)
        with pytest.raises(ValueError, match="Duplicate"):
            store.add(mode=3, wallet_name="alice", recipient="0xAbAb" * 5, amount=0.5)

    def test_different_amount_allowed(self, store):
        store.add(mode=3, wallet_name="alice", recipient="0xAbAb" * 5, amount=0.5)
        intent2 = store.add(mode=3, wallet_name="alice", recipient="0xAbAb" * 5, amount=1.0)
        assert intent2 is not None

    def test_sent_intent_does_not_block_new(self, store):
        intent = store.add(mode=3, wallet_name="alice", recipient="0xAbAb" * 5, amount=0.5)
        store.update_status(intent.id, IntentStatus.SENT, tx_hash="0xabc")
        # Now a new identical intent should be allowed
        intent2 = store.add(mode=3, wallet_name="alice", recipient="0xAbAb" * 5, amount=0.5)
        assert intent2.id != intent.id


class TestListIntents:
    def test_list_all(self, store):
        store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.add(mode=3, wallet_name="b", recipient="0x" + "cd" * 20, amount=2.0)
        assert len(store.list_intents()) == 2

    def test_list_by_status(self, store):
        i1 = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.add(mode=3, wallet_name="b", recipient="0x" + "cd" * 20, amount=2.0)
        store.update_status(i1.id, IntentStatus.SENT)
        assert len(store.list_intents(status=IntentStatus.PENDING)) == 1
        assert len(store.list_intents(status=IntentStatus.SENT)) == 1


class TestUpdateStatus:
    def test_update_status(self, store):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.update_status(intent.id, IntentStatus.SENDING)
        updated = store.get(intent.id)
        assert updated.status == IntentStatus.SENDING

    def test_update_with_error(self, store):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.update_status(intent.id, IntentStatus.PENDING, error="timeout")
        updated = store.get(intent.id)
        assert updated.last_error == "timeout"

    def test_update_with_tx_hash(self, store):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.update_status(intent.id, IntentStatus.SENT, tx_hash="0xdeadbeef")
        updated = store.get(intent.id)
        assert updated.result_tx_hash == "0xdeadbeef"


class TestIncrementAttempts:
    def test_increment(self, store):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.increment_attempts(intent.id)
        updated = store.get(intent.id)
        assert updated.attempts == 1
        assert updated.status == IntentStatus.PENDING

    def test_marks_failed_at_max(self, store):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        for _ in range(intent.max_attempts):
            store.increment_attempts(intent.id)
        updated = store.get(intent.id)
        assert updated.status == IntentStatus.FAILED
        assert updated.attempts == intent.max_attempts


class TestRemoveAndClear:
    def test_remove(self, store):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        assert store.remove(intent.id) is True
        assert store.get(intent.id) is None

    def test_remove_nonexistent(self, store):
        assert store.remove("doesnotexist") is False

    def test_clear_all(self, store):
        store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.add(mode=3, wallet_name="b", recipient="0x" + "cd" * 20, amount=2.0)
        removed = store.clear()
        assert removed == 2
        assert len(store.list_intents()) == 0

    def test_clear_by_status(self, store):
        i1 = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.add(mode=3, wallet_name="b", recipient="0x" + "cd" * 20, amount=2.0)
        store.update_status(i1.id, IntentStatus.SENT)
        removed = store.clear(status=IntentStatus.SENT)
        assert removed == 1
        assert len(store.list_intents()) == 1


class TestPendingIntents:
    def test_sorted_by_created_at(self, store):
        i1 = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        i2 = store.add(mode=3, wallet_name="b", recipient="0x" + "cd" * 20, amount=2.0)
        pending = store.pending_intents()
        assert len(pending) == 2
        assert pending[0].id == i1.id
        assert pending[1].id == i2.id


class TestEdgeCases:
    def test_empty_queue_file_missing(self, tmp_queue_dir):
        store = IntentStore(queue_dir=tmp_queue_dir)
        assert store.list_intents() == []
        assert store.pending_intents() == []

    def test_file_permissions(self, store):
        store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        mode = os.stat(store._queue_path).st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_sending_recovered_to_pending(self, store, tmp_queue_dir):
        intent = store.add(mode=3, wallet_name="a", recipient="0x" + "ab" * 20, amount=1.0)
        store.update_status(intent.id, IntentStatus.SENDING)
        assert store.get(intent.id).status == IntentStatus.SENDING

        # Simulate process restart -- reload from disk
        store2 = IntentStore(queue_dir=tmp_queue_dir)
        recovered = store2.get(intent.id)
        assert recovered.status == IntentStatus.PENDING

    def test_get_nonexistent(self, store):
        assert store.get("nope") is None

    def test_corrupted_json_returns_empty(self, tmp_queue_dir):
        queue_path = tmp_queue_dir / QUEUE_FILENAME
        queue_path.write_text("{invalid json!!!")
        store = IntentStore(queue_dir=tmp_queue_dir)
        assert store.list_intents() == []

    def test_corrupted_json_recoverable(self, tmp_queue_dir):
        """After loading corrupted file, new intents can be added."""
        queue_path = tmp_queue_dir / QUEUE_FILENAME
        queue_path.write_text("not json at all")
        store = IntentStore(queue_dir=tmp_queue_dir)
        intent = store.add(mode=3, wallet_name="a",
                           recipient="0x" + "ab" * 20, amount=1.0)
        assert store.get(intent.id) is not None

    def test_directory_permissions(self, tmp_path):
        d = tmp_path / "new_queue"
        store = IntentStore(queue_dir=d)
        mode = os.stat(d).st_mode
        assert stat.S_IMODE(mode) == 0o700

    def test_flush_lock(self, store):
        """flush_lock can be acquired and released."""
        with store.flush_lock():
            # Should be able to write while holding the lock
            store.add(mode=3, wallet_name="a",
                      recipient="0x" + "ab" * 20, amount=1.0)
        # Lock released, should still be accessible
        assert len(store.list_intents()) == 1
