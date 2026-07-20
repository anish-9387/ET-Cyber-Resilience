from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import asyncio
import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from app.core.logger import logger
from app.api.ingest import ingest_raw_event
from app.scenarios import SCENARIOS, get_scenario, list_scenarios

try:
    from app.world_model import world_model
    WORLD_MODEL_AVAILABLE = True
except ImportError:
    world_model = None
    WORLD_MODEL_AVAILABLE = False

router = APIRouter()

MAX_SLEEP_SECONDS = 30.0


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    speed: float = Field(default=60.0, gt=0, le=100000.0)
    reset_world_model: bool = False


class ScenarioRun:
    def __init__(self, run_id: str, scenario: Dict[str, Any], speed: float):
        self.run_id = run_id
        self.scenario_id = scenario["id"]
        self.scenario_name = scenario["name"]
        self.total_events = len(scenario["events"])
        self.speed = speed
        self.status = "pending"
        self.processed = 0
        self.failed = 0
        self.detected = 0
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.error: Optional[str] = None
        self.timeline: List[Dict[str, Any]] = []
        self.updated_entities: set = set()

    def progress(self) -> float:
        if self.total_events == 0:
            return 1.0
        return round(self.processed / self.total_events, 4)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "status": self.status,
            "speed": self.speed,
            "processed": self.processed,
            "failed": self.failed,
            "detected": self.detected,
            "total_events": self.total_events,
            "progress": self.progress(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "updated_entities": sorted(self.updated_entities),
            "timeline": self.timeline,
        }


_runs: Dict[str, ScenarioRun] = {}
_current_run_id: Optional[str] = None


async def _execute_scenario(run: ScenarioRun, scenario: Dict[str, Any], reset: bool):
    global _current_run_id
    run.status = "running"
    run.started_at = datetime.now(timezone.utc).isoformat()

    if reset and WORLD_MODEL_AVAILABLE:
        try:
            world_model.reset()
        except Exception as e:
            logger.warning("World model reset failed", error=str(e))

    previous_offset = 0.0
    try:
        for event in scenario["events"]:
            offset = float(event.get("offset_seconds", 0.0))
            delay = max(0.0, (offset - previous_offset) / run.speed)
            previous_offset = offset
            if delay > 0:
                await asyncio.sleep(min(delay, MAX_SLEEP_SECONDS))

            try:
                result = await ingest_raw_event(event)
            except Exception as e:
                run.failed += 1
                logger.warning("Scenario event failed", run_id=run.run_id, error=str(e))
                continue

            run.processed += 1
            run.updated_entities.update(result.get("updated_entities") or [])

            ground_truth = event.get("ground_truth", {})
            detected = bool(result["anomaly"]["is_anomalous"])
            if detected:
                run.detected += 1

            run.timeline.append({
                "offset_seconds": offset,
                "entity_id": result["entity_id"],
                "source": result["normalized"].get("source"),
                "title": result["normalized"].get("title"),
                "anomaly_score": result["anomaly"]["anomaly_score"],
                "detector": result["anomaly"]["detector"],
                "detected": detected,
                "predicted_technique": result["mitre"].get("technique_id"),
                "likelihood_ratio": result["likelihood_ratio"]["likelihood_ratio"],
                "ground_truth": ground_truth,
                "correct_technique": (
                    result["mitre"].get("technique_id") == ground_truth.get("true_technique")
                ),
            })

        run.status = "completed"
    except asyncio.CancelledError:
        run.status = "cancelled"
        raise
    except Exception as e:
        run.status = "failed"
        run.error = str(e)
        logger.error("Scenario run failed", run_id=run.run_id, error=str(e))
    finally:
        run.finished_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Scenario run finished",
            run_id=run.run_id,
            scenario_id=run.scenario_id,
            status=run.status,
            processed=run.processed,
            detected=run.detected,
        )


@router.get("/list")
async def get_scenario_list():
    return {"scenarios": list_scenarios(), "count": len(SCENARIOS)}


@router.post("/run")
async def run_scenario(request: ScenarioRunRequest, background_tasks: BackgroundTasks):
    global _current_run_id
    try:
        scenario = get_scenario(request.scenario_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{request.scenario_id}'. Available: {sorted(SCENARIOS)}",
        )

    active = _runs.get(_current_run_id) if _current_run_id else None
    if active and active.status == "running":
        raise HTTPException(
            status_code=409,
            detail=f"Scenario '{active.scenario_id}' is already running (run_id={active.run_id})",
        )

    run = ScenarioRun(str(uuid.uuid4()), scenario, request.speed)
    _runs[run.run_id] = run
    _current_run_id = run.run_id

    background_tasks.add_task(_execute_scenario, run, scenario, request.reset_world_model)

    return {
        "run_id": run.run_id,
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "status": "started",
        "speed": request.speed,
        "total_events": run.total_events,
        "simulated_duration_seconds": scenario["duration_seconds"],
        "estimated_wall_clock_seconds": round(scenario["duration_seconds"] / request.speed, 2),
    }


@router.get("/status")
async def scenario_status(run_id: Optional[str] = None):
    target_id = run_id or _current_run_id
    if not target_id or target_id not in _runs:
        return {
            "active": False,
            "run": None,
            "history": [r.snapshot()["run_id"] for r in _runs.values()],
        }

    run = _runs[target_id]
    snapshot = run.snapshot()

    if WORLD_MODEL_AVAILABLE:
        try:
            entities = world_model.all_entities()
            snapshot["world_model"] = {
                "entity_count": len(entities),
                "compromised_count": len(
                    [e for e in entities if float(getattr(e, "p_compromised", 0.0)) > 0.5]
                ),
            }
        except Exception as e:
            snapshot["world_model"] = {"error": str(e)}

    return {
        "active": run.status == "running",
        "run": snapshot,
        "history": list(_runs.keys()),
    }
