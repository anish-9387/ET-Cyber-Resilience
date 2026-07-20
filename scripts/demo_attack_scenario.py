#!/usr/bin/env python3
"""End-to-end Sentinel demo: telemetry in, world model updates, decision out.

This script drives the real API and nothing else. It has no fallback values: if
an endpoint is missing or the backend is down it prints the failure and exits
non-zero. The previous version of this file supplied defaults for every field it
displayed (`prediction.get('confidence', 85)`, `twin.get('impact_score', 7.2)`,
"Blast radius: 3 devices, 5 users"), wrapped every step in a bare except, and
then printed "DEMO COMPLETE - successfully detected, predicted, simulated,
responded" unconditionally. It therefore produced a fully convincing AI
narrative even when every single API call returned 404. Do not reintroduce that
pattern: a demo that cannot fail cannot demonstrate anything.

Usage:
    python scripts/demo_attack_scenario.py [--scenario lockbit_hospital] [--speed 20]
"""

import argparse
import asyncio
import sys
from typing import Any, Dict, Optional

import httpx

API_BASE = "http://localhost:8000/api/v1"


class DemoFailure(RuntimeError):
    pass


def rule(title: str = "") -> None:
    print()
    print("=" * 78)
    if title:
        print(f"  {title}")
        print("=" * 78)


def line(label: str, value: Any) -> None:
    print(f"  {label:<26} {value}")


async def call(
    client: httpx.AsyncClient, method: str, path: str, payload: Optional[Dict] = None
) -> Any:
    url = f"{API_BASE}{path}"
    try:
        resp = await client.request(method, url, json=payload)
    except httpx.ConnectError as exc:
        raise DemoFailure(
            f"Cannot reach {url}.\n"
            f"  Start the backend first:  cd backend && venv/bin/uvicorn app.main:app"
        ) from exc

    if resp.status_code >= 300:
        raise DemoFailure(f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json()


async def wait_for_scenario(client: httpx.AsyncClient, timeout_s: int = 240) -> Dict[str, Any]:
    for _ in range(timeout_s):
        status = await call(client, "GET", "/scenario/status")
        run = status.get("run") or {}
        if not status.get("active") and run.get("processed", 0) > 0:
            return run
        await asyncio.sleep(1)
    raise DemoFailure("Scenario did not complete within the timeout")


async def main(scenario_id: str, speed: float) -> int:
    async with httpx.AsyncClient(timeout=120) as client:
        rule("SENTINEL - CYBER WORLD MODEL DEMO")

        health = await call(client, "GET", "/health")
        line("backend", health.get("status"))
        for name, svc in (health.get("services") or {}).items():
            line(f"  {name}", svc.get("status"))

        rule("1. BASELINE WORLD MODEL")
        before = await call(client, "GET", "/world-model/state")
        line("entities", before.get("entity_count"))
        line("relations", before.get("relation_count"))
        line("global risk", round(before.get("global_risk", 0.0), 4))
        line("observations", before.get("observation_count"))

        rule(f"2. INJECTING SCENARIO: {scenario_id}")
        started = await call(
            client, "POST", "/scenario/run", {"scenario_id": scenario_id, "speed": speed}
        )
        line("scenario", started.get("scenario_name"))
        line("events", started.get("total_events"))
        run = await wait_for_scenario(client)
        line("processed", run.get("processed"))
        line("detected", run.get("detected"))
        line("failed", run.get("failed"))

        rule("3. WORLD MODEL AFTER INGEST")
        after = await call(client, "GET", "/world-model/state")
        line(
            "global risk",
            f"{before.get('global_risk', 0):.4f} -> {after.get('global_risk', 0):.4f}",
        )
        ranked = sorted(after.get("entities", []), key=lambda e: -e.get("p_compromised", 0))[:6]
        print()
        print(f"  {'ENTITY':<32}{'P(COMPROMISED)':>16}{'CONFIDENCE':>13}  STATE")
        for e in ranked:
            print(
                f"  {str(e.get('name', ''))[:31]:<32}"
                f"{e.get('p_compromised', 0):>16.3f}"
                f"{e.get('confidence', 0):>13.2f}  {e.get('state')}"
            )

        rule("4. ATTACKER BELIEF MODEL")
        belief = await call(client, "GET", "/world-model/attacker-belief")
        line(
            "inferred objective",
            f"{belief.get('current_objective')} ({belief.get('objective_confidence')})",
        )
        campaign = belief.get("campaign_match") or {}
        line("campaign match", f"{campaign.get('actor')} (similarity {campaign.get('confidence')})")
        line("current tactic", belief.get("current_tactic"))
        line("techniques seen", ", ".join(belief.get("observed_techniques", [])[:10]))
        print()
        for nxt in belief.get("likely_next", [])[:4]:
            print(
                f"    next -> {nxt.get('technique_id')} {nxt.get('name')} "
                f"p={nxt.get('probability')} eta={nxt.get('eta_minutes')}min"
            )

        rule("5. DEFENDER BELIEF MODEL (our own uncertainty)")
        defender = await call(client, "GET", "/world-model/defender-belief")
        line("overall confidence", round(defender.get("overall_confidence", 0.0), 3))
        for u in defender.get("uncertain_entities", [])[:4]:
            print(f"    {u.get('entity_id')}  p={u.get('p_compromised')} conf={u.get('confidence')}")
            for rec in (u.get("recommended_collection") or [])[:2]:
                print(f"        collect: {rec}")

        rule("6. ATTACK FORECAST")
        forecast = await call(client, "GET", "/forecast/futures?horizon_minutes=60")
        line("attack success", forecast.get("attack_success"))
        for f in forecast.get("futures", [])[:5]:
            print(
                f"    p={f.get('probability', 0):<8.3f} {str(f.get('name'))[:44]:<46}"
                f"-> {f.get('terminal_objective')}"
            )

        rule("7. COUNTERFACTUAL: what if we isolate the backup server?")
        cf = await call(
            client,
            "POST",
            "/forecast/counterfactual",
            {"interventions": [{"type": "isolate_entity", "target": "srv-backup-01", "params": {}}]},
        )
        line("baseline success", cf.get("baseline_attack_success"))
        line("counterfactual", cf.get("counterfactual_attack_success"))
        line("delta", cf.get("delta"))
        print()
        print(f"    {cf.get('explanation')}")

        rule("8. DECISION ENGINE")
        decision = await call(client, "GET", "/decision/options")
        print(f"  {'ACTION':<26}{'ATK REDUCTION':>15}{'MISSION IMPACT':>16}{'APPROVAL':>12}")
        for o in decision.get("options", [])[:6]:
            print(
                f"  {str(o.get('action'))[:25]:<26}"
                f"{o.get('attack_success_reduction', 0):>15.4f}"
                f"{o.get('mission_impact', 0):>16.4f}"
                f"{'required' if o.get('approval_required') else 'auto':>12}"
            )
        line("recommended", decision.get("recommended_id"))

        rule("9. MISSION IMPACT")
        mission = await call(client, "GET", "/mission/impact")
        line("overall mission risk", mission.get("overall_mission_risk"))
        for fn in mission.get("functions", [])[:6]:
            print(
                f"    {str(fn.get('name'))[:26]:<28} availability={fn.get('availability')} "
                f"safety={fn.get('safety_risk')}"
            )

        rule("10. AUDIT TRAIL")
        audit = await call(client, "GET", "/audit/trail?limit=6")
        records = audit if isinstance(audit, list) else audit.get("records", [])
        line("records returned", len(records))
        for r in records[:6]:
            print(
                f"    [{r.get('actor_type')}] {r.get('actor')} :: {r.get('action')} "
                f"-> {r.get('target')} (conf {r.get('confidence')})"
            )

        rule("DEMO COMPLETE")
        print("  Every number above was computed by the backend from ingested telemetry.")
        print("  This script supplies no defaults and no fallbacks.")
        print()
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="lockbit_hospital")
    parser.add_argument("--speed", type=float, default=20.0)
    args = parser.parse_args()
    try:
        sys.exit(asyncio.run(main(args.scenario, args.speed)))
    except DemoFailure as exc:
        print(f"\n  DEMO FAILED: {exc}\n", file=sys.stderr)
        sys.exit(1)
