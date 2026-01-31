"""Persistent intent queue for store-and-forward transactions.

Stores transaction intents locally so they can be sent later when a
gateway becomes available.  Intents are stored as JSON -- no private
keys or passphrases are ever written to disk.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from basemesh.constants import MAX_FLUSH_ATTEMPTS

logger = logging.getLogger(__name__)

DEFAULT_QUEUE_DIR = Path.home() / ".basemesh"
QUEUE_FILENAME = "queue.json"
QUEUE_VERSION = 1


class IntentStatus:
    """Status values for queued intents."""

    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"


@dataclass
class Intent:
    """A stored transaction intent."""

    id: str
    mode: int  # 1 (relay) or 3 (gateway request)
    status: str
    created_at: int
    updated_at: int
    wallet_name: str
    recipient: str
    amount: float
    token_address: Optional[str] = None
    token_decimals: int = 18
    attempts: int = 0
    max_attempts: int = MAX_FLUSH_ATTEMPTS
    last_error: Optional[str] = None
    result_tx_hash: Optional[str] = None


class IntentStore:
    """Manages the on-disk intent queue at ``<queue_dir>/queue.json``."""

    def __init__(self, queue_dir: Path = DEFAULT_QUEUE_DIR):
        self._queue_dir = Path(queue_dir)
        self._queue_dir.mkdir(parents=True, exist_ok=True)
        self._queue_path = self._queue_dir / QUEUE_FILENAME
        self._recover_stale_sending()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _recover_stale_sending(self) -> None:
        """Recover intents stuck in SENDING from a previous crashed flush."""
        intents = self._load()
        changed = False
        for intent in intents:
            if intent.status == IntentStatus.SENDING:
                intent.status = IntentStatus.PENDING
                intent.updated_at = int(time.time())
                changed = True
        if changed:
            self._save(intents)

    def _load(self) -> list[Intent]:
        """Load all intents from disk."""
        if not self._queue_path.exists():
            return []

        with open(self._queue_path, "r") as f:
            data = json.load(f)

        intents: list[Intent] = []
        for raw in data.get("intents", []):
            intents.append(Intent(**raw))
        return intents

    def _save(self, intents: list[Intent]) -> None:
        """Atomically write intents to disk (write-tmp-then-rename)."""
        data = {
            "version": QUEUE_VERSION,
            "intents": [asdict(i) for i in intents],
        }
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._queue_dir), suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self._queue_path)
        except BaseException:
            # Clean up temp file on any failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(
        self,
        mode: int,
        wallet_name: str,
        recipient: str,
        amount: float,
        token_address: Optional[str] = None,
        token_decimals: int = 18,
    ) -> Intent:
        """Create and persist a new intent.

        Raises ``ValueError`` if a duplicate pending intent already exists
        (same wallet, recipient, amount, and token).
        """
        if mode not in (1, 3):
            raise ValueError("mode must be 1 or 3")

        intents = self._load()

        # Deduplication check
        dedup = self._dedup_key(wallet_name, recipient, amount, token_address)
        for existing in intents:
            if existing.status == IntentStatus.PENDING:
                if self._dedup_key(
                    existing.wallet_name, existing.recipient,
                    existing.amount, existing.token_address,
                ) == dedup:
                    raise ValueError("Duplicate intent already queued")

        now = int(time.time())
        intent = Intent(
            id=os.urandom(4).hex(),
            mode=mode,
            status=IntentStatus.PENDING,
            created_at=now,
            updated_at=now,
            wallet_name=wallet_name,
            recipient=recipient,
            amount=amount,
            token_address=token_address,
            token_decimals=token_decimals,
        )
        intents.append(intent)
        self._save(intents)
        logger.info("Added intent %s: mode=%d %s -> %s amount=%s",
                     intent.id, mode, wallet_name, recipient, amount)
        return intent

    def list_intents(self, status: Optional[str] = None) -> list[Intent]:
        """Return all intents, optionally filtered by status."""
        intents = self._load()
        if status is not None:
            intents = [i for i in intents if i.status == status]
        return intents

    def get(self, intent_id: str) -> Optional[Intent]:
        """Return a single intent by ID, or ``None``."""
        for intent in self._load():
            if intent.id == intent_id:
                return intent
        return None

    def update_status(
        self,
        intent_id: str,
        status: str,
        error: Optional[str] = None,
        tx_hash: Optional[str] = None,
    ) -> None:
        """Update an intent's status (and optionally error / tx_hash)."""
        intents = self._load()
        for intent in intents:
            if intent.id == intent_id:
                intent.status = status
                intent.updated_at = int(time.time())
                if error is not None:
                    intent.last_error = error
                if tx_hash is not None:
                    intent.result_tx_hash = tx_hash
                break
        self._save(intents)

    def increment_attempts(self, intent_id: str) -> None:
        """Increment the attempt counter.

        If ``max_attempts`` is reached the intent is marked FAILED.
        """
        intents = self._load()
        for intent in intents:
            if intent.id == intent_id:
                intent.attempts += 1
                intent.updated_at = int(time.time())
                if intent.attempts >= intent.max_attempts:
                    intent.status = IntentStatus.FAILED
                    intent.last_error = (
                        intent.last_error or "Max attempts reached"
                    )
                break
        self._save(intents)

    def remove(self, intent_id: str) -> bool:
        """Remove an intent by ID.  Returns ``True`` if found."""
        intents = self._load()
        before = len(intents)
        intents = [i for i in intents if i.id != intent_id]
        if len(intents) == before:
            return False
        self._save(intents)
        return True

    def clear(self, status: Optional[str] = None) -> int:
        """Remove intents.  If *status* is given only those are removed.

        Returns the number of intents removed.
        """
        intents = self._load()
        before = len(intents)
        if status is not None:
            intents = [i for i in intents if i.status != status]
        else:
            intents = []
        removed = before - len(intents)
        self._save(intents)
        return removed

    def pending_intents(self) -> list[Intent]:
        """Return all PENDING intents sorted by ``created_at``."""
        return sorted(
            self.list_intents(status=IntentStatus.PENDING),
            key=lambda i: i.created_at,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup_key(
        wallet_name: str,
        recipient: str,
        amount: float,
        token_address: Optional[str],
    ) -> tuple:
        return (wallet_name, recipient.lower(), amount,
                (token_address or "").lower())
