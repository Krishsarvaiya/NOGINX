"""Rolling (idle-timeout) session builder.

A session begins on a client's first request and stays open as long as
requests keep arriving within `idle_timeout` of the previous one. It only
closes after that much silence -- never on a fixed tumbling window.

This replaces THREAT_DETECTION_PIPELINE.py's previous 5-minute
tumbling-window logic, which -- because its timestamps failed to parse --
degenerated into one session per request.

Offline replay and live tailing share this exact class: offline passes
each record's own timestamp as `now` (event-time replay); live passes the
wall clock. The builder itself never reads the system clock.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta
from typing import Optional

from core.models import LogRecord, Session

DEFAULT_IDLE_TIMEOUT = timedelta(minutes=5)
DEFAULT_KEY_FIELDS = ("source_ip", "user_agent")


class RollingSessionBuilder:
    def __init__(
        self,
        idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
        key_fields: tuple[str, ...] = DEFAULT_KEY_FIELDS,
    ):
        self.idle_timeout = idle_timeout
        self.key_fields = key_fields
        self._open: dict[str, Session] = {}
        self._id_counter = itertools.count(1)

    def _session_key(self, record: LogRecord) -> str:
        """Join whichever configured key fields are present.

        Defaults to source_ip + user_agent, automatically falling back to
        source_ip alone when user_agent is unavailable (e.g. the CSV
        fixture used by the offline pipeline has no user_agent field).
        """
        parts = [str(getattr(record, name)) for name in self.key_fields if getattr(record, name, None)]
        return "|".join(parts) if parts else record.source_ip

    def add_record(self, record: LogRecord, now: Optional[datetime] = None) -> list[Session]:
        """Feed one record (must be fed in non-decreasing timestamp order
        per key). Returns the previous session under the same key if it
        had gone idle and was just closed to make room for this record.
        """
        now = now if now is not None else record.timestamp
        key = self._session_key(record)
        closed: list[Session] = []

        existing = self._open.get(key)
        if existing is not None and (now - existing.last_activity) > self.idle_timeout:
            existing.closed_at = existing.last_activity
            closed.append(existing)
            del self._open[key]
            existing = None

        if existing is None:
            existing = Session(
                session_id=f"session_{next(self._id_counter)}",
                session_key=key,
                source_ip=record.source_ip,
                user_agent=record.user_agent,
                started_at=record.timestamp,
                last_activity=record.timestamp,
            )
            self._open[key] = existing

        existing.records.append(record)
        existing.last_activity = record.timestamp
        return closed

    def sweep(self, now: datetime) -> list[Session]:
        """Close every session idle longer than idle_timeout as of `now`."""
        closed = []
        for key, session in list(self._open.items()):
            if (now - session.last_activity) > self.idle_timeout:
                session.closed_at = session.last_activity
                closed.append(session)
                del self._open[key]
        return closed

    def flush_all(self) -> list[Session]:
        """Force-close every still-open session (end of stream/shutdown)."""
        closed = list(self._open.values())
        for session in closed:
            session.closed_at = session.last_activity
        self._open.clear()
        return closed

    def open_sessions(self) -> list[Session]:
        """Snapshot of currently open sessions, without closing them.

        A session that keeps actively receiving records never appears in
        add_record()'s or sweep()'s return values, since both only report
        sessions that have gone idle. Without a way to look at open
        sessions, a sustained, continuously active session (a real
        ongoing attack, or just a burst of test traffic) would never get
        evaluated at all until its source finally goes quiet for
        idle_timeout -- defeating the point of live detection. Callers
        that need periodic visibility into in-progress sessions use this;
        it does not mutate builder state.
        """
        return list(self._open.values())
