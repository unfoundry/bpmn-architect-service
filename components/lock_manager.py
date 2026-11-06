"""
==============================================================================
BPMN Architect Service - Cooperative Soft Lock & Presence Manager
==============================================================================
Manages concurrent access to BPMN diagram files using an in-memory, thread-safe
cooperative soft-lock pattern.

Core Design Principles:
1. Prevents accidental overwrites by allowing only one active writer at a time.
2. Cooperative Handoff: Instead of hard kick-outs, users can politely request
   the edit token. The current editor is notified on their next heartbeat.
3. Natural Expiration: If a user closes their laptop or loses connection, the
   lock naturally expires after a configurable grace window (no hostage locks).
4. Live Presence: Tracks active viewers so collaborators see who is viewing
   the process diagram.
==============================================================================
"""

import time
import asyncio
from typing import Dict, Optional, List, Set, Any
from dataclasses import dataclass, field

import config


@dataclass
class DiagramLockState:
    """
    Internal state tracking for an individual diagram's edit session.
    """
    diagram_id: str
    locked_by: Optional[str] = None
    locked_at: float = 0.0
    expires_at: float = 0.0
    last_heartbeat: float = 0.0
    pending_handoff_to: Optional[str] = None
    # Dictionary mapping username -> last_seen_epoch_seconds
    viewers: Dict[str, float] = field(default_factory=dict)

    def is_active(self, current_time: float) -> bool:
        """Returns True if the lock is held and has not expired."""
        return bool(self.locked_by and self.expires_at > current_time)

    def seconds_remaining(self, current_time: float) -> int:
        """Returns remaining seconds on the lock, or 0 if expired."""
        if not self.is_active(current_time):
            return 0
        return max(0, int(self.expires_at - current_time))

    def clean_stale_viewers(self, current_time: float, max_idle_sec: int = 45):
        """Removes viewers who haven't pinged within max_idle_sec."""
        stale = [u for u, last_seen in self.viewers.items() if (current_time - last_seen) > max_idle_sec]
        for u in stale:
            del self.viewers[u]


class LockManager:
    """
    Thread-safe coordinator for diagram locks and collaborator presence.
    """
    def __init__(self):
        # Maps diagram_id -> DiagramLockState
        self._locks: Dict[str, DiagramLockState] = {}
        # Mutex lock for async operations
        self._mutex = asyncio.Lock()

    def _get_or_create(self, diagram_id: str) -> DiagramLockState:
        if diagram_id not in self._locks:
            self._locks[diagram_id] = DiagramLockState(diagram_id=diagram_id)
        return self._locks[diagram_id]

    async def acquire_lock(self, diagram_id: str, username: str) -> Dict[str, Any]:
        """
        Attempts to acquire the exclusive edit token for a diagram.
        Succeeds if:
        - The diagram is unlocked.
        - The current lock has expired.
        - The user already holds the active lock.
        """
        async with self._mutex:
            now = time.time()
            state = self._get_or_create(diagram_id)
            state.clean_stale_viewers(now)

            # Case 1: Already held by this user -> extend lock
            if state.locked_by == username and state.is_active(now):
                state.expires_at = now + config.TOTAL_LOCK_EXPIRY_SEC
                state.last_heartbeat = now
                return {
                    "success": True,
                    "status": "extended",
                    "locked_by": username,
                    "expires_in_sec": state.seconds_remaining(now),
                    "pending_handoff_to": state.pending_handoff_to,
                }

            # Case 2: Unlocked or previous lock expired
            if not state.is_active(now):
                state.locked_by = username
                state.locked_at = now
                state.last_heartbeat = now
                state.expires_at = now + config.TOTAL_LOCK_EXPIRY_SEC
                state.pending_handoff_to = None
                return {
                    "success": True,
                    "status": "acquired",
                    "locked_by": username,
                    "expires_in_sec": state.seconds_remaining(now),
                    "pending_handoff_to": None,
                }

            # Case 3: Locked by another user and not expired
            return {
                "success": False,
                "status": "locked",
                "locked_by": state.locked_by,
                "expires_in_sec": state.seconds_remaining(now),
                "pending_handoff_to": state.pending_handoff_to,
                "message": f"Diagram is currently being edited by '{state.locked_by}'.",
            }

    async def heartbeat(self, diagram_id: str, username: str) -> Dict[str, Any]:
        """
        Renews an active lock. If another user has requested handoff,
        informs the active editor in the response.
        """
        async with self._mutex:
            now = time.time()
            state = self._get_or_create(diagram_id)
            state.clean_stale_viewers(now)
            state.viewers[username] = now

            if state.locked_by != username:
                return {
                    "success": False,
                    "status": "lock_lost",
                    "locked_by": state.locked_by,
                    "message": "You do not hold the active edit token for this diagram.",
                }

            # Extend expiration
            state.expires_at = now + config.TOTAL_LOCK_EXPIRY_SEC
            state.last_heartbeat = now

            return {
                "success": True,
                "status": "heartbeat_ok",
                "locked_by": username,
                "expires_in_sec": state.seconds_remaining(now),
                "pending_handoff_to": state.pending_handoff_to,
            }

    async def release_lock(self, diagram_id: str, username: str, force: bool = False) -> Dict[str, Any]:
        """
        Releases the edit token. Normal users can only release locks they hold.
        Admins can force release locks held by others.
        """
        async with self._mutex:
            now = time.time()
            state = self._get_or_create(diagram_id)

            if state.locked_by == username or force:
                old_owner = state.locked_by
                state.locked_by = None
                state.expires_at = 0.0
                pending = state.pending_handoff_to
                state.pending_handoff_to = None
                return {
                    "success": True,
                    "status": "released",
                    "previous_owner": old_owner,
                    "pending_handoff_to": pending,
                }

            return {
                "success": False,
                "status": "not_authorized",
                "message": "Cannot release a lock held by another user without admin privileges.",
            }

    async def request_handoff(self, diagram_id: str, requester: str) -> Dict[str, Any]:
        """
        Submits a polite request to the current lock holder to save and hand off the edit token.
        """
        async with self._mutex:
            now = time.time()
            state = self._get_or_create(diagram_id)

            if not state.is_active(now):
                # Lock is actually free, advise requester to acquire directly
                return {
                    "success": True,
                    "status": "unlocked",
                    "message": "Diagram is currently unlocked. You may acquire the token directly.",
                }

            if state.locked_by == requester:
                return {
                    "success": True,
                    "status": "already_owner",
                    "message": "You already hold the active edit token.",
                }

            # Record pending handoff target
            state.pending_handoff_to = requester
            return {
                "success": True,
                "status": "handoff_requested",
                "locked_by": state.locked_by,
                "message": f"Handoff request delivered. '{state.locked_by}' has been notified.",
            }

    async def ping_presence(self, diagram_id: str, username: str) -> Dict[str, Any]:
        """
        Updates the presence timestamp for a user viewing or editing the diagram.
        """
        async with self._mutex:
            now = time.time()
            state = self._get_or_create(diagram_id)
            state.viewers[username] = now
            state.clean_stale_viewers(now)

            return {
                "active_viewers": list(state.viewers.keys()),
                "is_locked": state.is_active(now),
                "locked_by": state.locked_by if state.is_active(now) else None,
                "expires_in_sec": state.seconds_remaining(now),
            }

    async def get_status(self, diagram_id: str) -> Dict[str, Any]:
        """
        Returns full lock status, expiration, and active viewers for a diagram.
        """
        async with self._mutex:
            now = time.time()
            state = self._get_or_create(diagram_id)
            state.clean_stale_viewers(now)

            is_locked = state.is_active(now)
            return {
                "diagram_id": diagram_id,
                "is_locked": is_locked,
                "locked_by": state.locked_by if is_locked else None,
                "expires_in_sec": state.seconds_remaining(now),
                "pending_handoff_to": state.pending_handoff_to if is_locked else None,
                "active_viewers": list(state.viewers.keys()),
            }


# Global singleton lock manager
lock_manager = LockManager()

