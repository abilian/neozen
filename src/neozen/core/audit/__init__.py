"""Audit logging for NeoZen.

Provides comprehensive audit logging for security-relevant events.
"""

from __future__ import annotations

from neozen.core.audit.event_handler import (
    AuditEventHandler,
    create_audit_handler,
    setup_audit_logging,
)
from neozen.core.audit.logger import AuditLogger
from neozen.core.audit.store import AuditLogStore, InMemoryAuditLogStore
from neozen.core.audit.types import AuditActions, AuditLogEntry, AuditOutcome

__all__ = [
    "AuditActions",
    "AuditEventHandler",
    "AuditLogger",
    "AuditLogEntry",
    "AuditLogStore",
    "AuditOutcome",
    "InMemoryAuditLogStore",
    "create_audit_handler",
    "setup_audit_logging",
]
