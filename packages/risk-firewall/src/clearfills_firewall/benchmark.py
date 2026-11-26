"""Policy Regression & Bypass Suite entrypoint for clearfills-firewall."""

from __future__ import annotations

from .policy_compiler import (
    SUITE_TITLE,
    BenchmarkReport,
    BenchmarkScenarioResult,
    run_safety_benchmark,
)

run_policy_regression_suite = run_safety_benchmark

__all__ = [
    "SUITE_TITLE",
    "BenchmarkReport",
    "BenchmarkScenarioResult",
    "run_policy_regression_suite",
    "run_safety_benchmark",
]
