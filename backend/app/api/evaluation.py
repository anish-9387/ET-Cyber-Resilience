"""`/evaluation/*` routes - serves computed benchmark results.

Every payload here is produced by ``app.evaluation.runner`` at run time from
the real detector, mapper, playbooks and world model. No figure is hardcoded.

The GET routes serve the cached report from the last completed run. They do NOT
silently trigger a run, because a full evaluation takes seconds to minutes and a
GET should not block; instead they return HTTP 409 with instructions to POST
``/evaluation/run`` first. ``?run_if_missing=true`` opts into a blocking run.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from app.core.logger import logger
from app.evaluation.datasets import DEFAULT_SEED
from app.evaluation.runner import (
    get_last_report,
    is_running,
    run_full_evaluation,
)

router = APIRouter()

_NO_REPORT_DETAIL = (
    "No evaluation report available yet. POST /api/v1/evaluation/run to compute "
    "one, then retry. Pass ?run_if_missing=true to run synchronously (slow)."
)


async def _report_or_409(run_if_missing: bool) -> Dict[str, Any]:
    report = get_last_report()
    if report is not None:
        return report
    if not run_if_missing:
        raise HTTPException(status_code=409, detail=_NO_REPORT_DETAIL)
    return await run_full_evaluation()


def _section(report: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Attach shared run metadata to a single section of the report."""
    section = report.get(name)
    if section is None:
        raise HTTPException(
            status_code=500,
            detail=f"Report is missing the '{name}' section.",
        )
    return {
        **section,
        "generated_at": report.get("generated_at"),
        "seed": report.get("seed"),
        "dataset_provenance": report.get("dataset_provenance"),
    }


@router.get("/detection")
async def get_detection(
    run_if_missing: bool = Query(False),
) -> Dict[str, Any]:
    """Anomaly detection rate and false positive rate on the benchmark corpus."""
    report = await _report_or_409(run_if_missing)
    return _section(report, "detection")


@router.get("/attribution")
async def get_attribution(
    run_if_missing: bool = Query(False),
) -> Dict[str, Any]:
    """ATT&CK attribution accuracy, with explicit catalogue-coverage limits."""
    report = await _report_or_409(run_if_missing)
    return _section(report, "attribution")


@router.get("/response-coverage")
async def get_response_coverage(
    run_if_missing: bool = Query(False),
) -> Dict[str, Any]:
    """Playbook automation coverage.

    Distinguishes ``steps_automatable_by_policy`` from
    ``steps_with_real_integration`` and always carries ``execution_mode``.
    """
    report = await _report_or_409(run_if_missing)
    return _section(report, "response_coverage")


@router.get("/mttd-mttr")
async def get_mttd_mttr(
    run_if_missing: bool = Query(False),
    include_trajectories: bool = Query(False),
) -> Dict[str, Any]:
    """MTTD/MTTR measured from replayed belief trajectories."""
    report = await _report_or_409(run_if_missing)
    section = _section(report, "mttd_mttr")
    if not include_trajectories:
        section.pop("_trajectories", None)
    return section


@router.get("/report")
async def get_full_report(
    run_if_missing: bool = Query(False),
) -> Dict[str, Any]:
    """The complete consolidated report across all criteria."""
    report = await _report_or_409(run_if_missing)
    trimmed = dict(report)
    timing = trimmed.get("mttd_mttr")
    if isinstance(timing, dict):
        timing = dict(timing)
        timing.pop("_trajectories", None)
        trimmed["mttd_mttr"] = timing
    return trimmed


@router.get("/status")
async def get_status() -> Dict[str, Any]:
    """Whether a report exists and whether a run is currently in flight."""
    report = get_last_report()
    return {
        "running": is_running(),
        "has_report": report is not None,
        "generated_at": report.get("generated_at") if report else None,
        "seed": report.get("seed") if report else None,
        "duration_seconds": report.get("duration_seconds") if report else None,
        "dataset": (
            report.get("dataset_provenance", {}).get("dataset") if report else None
        ),
    }


@router.post("/run")
async def trigger_run(
    background_tasks: BackgroundTasks,
    seed: int = Query(DEFAULT_SEED),
    benign_count: int = Query(4000, ge=100, le=100_000),
    scenario_repeats: int = Query(4, ge=1, le=50),
    external_dataset_path: Optional[str] = Query(None),
    wait: bool = Query(False, description="Run synchronously and return the report"),
) -> Dict[str, Any]:
    """Trigger a fresh evaluation run.

    Defaults to a background task returning HTTP 202 immediately; poll
    ``GET /evaluation/status``. Pass ``wait=true`` to block and get the report.
    """
    if is_running():
        raise HTTPException(
            status_code=409,
            detail="An evaluation run is already in progress.",
        )

    kwargs = {
        "seed": seed,
        "benign_count": benign_count,
        "scenario_repeats": scenario_repeats,
        "external_dataset_path": external_dataset_path,
    }

    if wait:
        report = await run_full_evaluation(**kwargs)
        trimmed = dict(report)
        timing = trimmed.get("mttd_mttr")
        if isinstance(timing, dict):
            timing = dict(timing)
            timing.pop("_trajectories", None)
            trimmed["mttd_mttr"] = timing
        return {"status": "completed", "report": trimmed}

    background_tasks.add_task(run_full_evaluation, **kwargs)
    logger.info("evaluation.api: background run queued", seed=seed)
    return {
        "status": "started",
        "message": (
            "Evaluation running in the background. Poll GET "
            "/api/v1/evaluation/status, then read the results endpoints."
        ),
        "seed": seed,
    }
