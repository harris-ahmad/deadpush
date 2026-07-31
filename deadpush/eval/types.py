"""Shared types for the thesis eval harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScenarioResult:
    """Outcome of one (scenario, baseline) run."""

    scenario: str
    baseline: str
    blocked: bool
    lasting_damage: bool
    useful_total: int
    useful_preserved: int
    false_positive: bool
    time_to_safe_ms: float
    time_to_recover_ms: float
    overhead_ms: float
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def work_preserved(self) -> float:
        if self.useful_total <= 0:
            return 1.0
        return self.useful_preserved / self.useful_total

    @property
    def block_rate(self) -> float:
        """1.0 if a dangerous lasting effect was prevented, else 0.0.

        For benign scenarios (false-positive probes), block_rate is unused (0).
        """
        if self.false_positive:
            return 0.0
        return 1.0 if self.blocked and not self.lasting_damage else 0.0


@dataclass
class EvalRow:
    """Flat CSV row derived from ``ScenarioResult``."""

    scenario: str
    baseline: str
    blocked: int
    lasting_damage: int
    block_rate: float
    work_preserved: float
    false_positive: int
    time_to_safe_ms: float
    time_to_recover_ms: float
    overhead_ms: float
    useful_total: int
    useful_preserved: int
    notes: str

    @classmethod
    def from_result(cls, r: ScenarioResult) -> EvalRow:
        return cls(
            scenario=r.scenario,
            baseline=r.baseline,
            blocked=int(r.blocked),
            lasting_damage=int(r.lasting_damage),
            block_rate=r.block_rate,
            work_preserved=r.work_preserved,
            false_positive=int(r.false_positive),
            time_to_safe_ms=r.time_to_safe_ms,
            time_to_recover_ms=r.time_to_recover_ms,
            overhead_ms=r.overhead_ms,
            useful_total=r.useful_total,
            useful_preserved=r.useful_preserved,
            notes=r.notes,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
