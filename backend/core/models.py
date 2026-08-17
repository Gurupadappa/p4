"""Typed data model shared by every pipeline stage."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class Stage(str, Enum):
    PREPARE = "prepare"
    SCAN = "scan"
    VALIDATE = "validate"
    PROVE = "prove"
    DONE = "done"


class ValidationVerdict(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class ApprovalStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"


SLA_BREACH_SECONDS = 72 * 3600  # 72h remediation SLA for confirmed criticals/highs


@dataclass
class Finding:
    """One candidate (later possibly confirmed) vulnerability."""

    id: str
    run_id: str
    repo: str
    file: str
    line: int
    rule_id: str
    vuln_class: str  # our vuln_class tag, or slugified from Semgrep registry metadata
    severity: str
    message: str
    code_snippet: str
    ground_truth_tag: str | None = None  # only set for demo/eval repos

    # Validate stage output
    verdict: ValidationVerdict = ValidationVerdict.PENDING
    rationale: str = ""
    confidence: float = 0.0
    dedup_signature: str | None = None
    dedup_group_id: str | None = None
    is_dedup_primary: bool = True

    # Prove stage output
    poc: str | None = None
    poc_explanation: str | None = None

    # Verify stage output: real, sandboxed exploitation of the finding.
    # None means "not attempted" (no sandbox registered, or Docker
    # unavailable) — distinct from False ("attempted, did not reproduce").
    verified: bool | None = None
    verification_detail: str | None = None

    # Lifecycle / SLA / approval
    first_seen: float = field(default_factory=time.time)
    approval_status: ApprovalStatus = ApprovalStatus.NOT_APPLICABLE
    fix_patch: str | None = None

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["verdict"] = self.verdict.value
        d["approval_status"] = self.approval_status.value
        age = time.time() - self.first_seen
        d["age_seconds"] = age
        d["sla_breached"] = self.verdict == ValidationVerdict.CONFIRMED and age > SLA_BREACH_SECONDS
        return d


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


@dataclass
class PipelineRun:
    id: str
    repos: list[str]
    stage: Stage = Stage.PREPARE
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["stage"] = self.stage.value
        return d
