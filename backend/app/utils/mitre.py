import json
from typing import Optional, List, Dict, Any
from pathlib import Path
from app.core.config import settings
from app.core.logger import logger


class MITREAttackManager:
    def __init__(self):
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._tactics: Dict[str, Dict[str, Any]] = {}
        self._groups: Dict[str, Dict[str, Any]] = {}
        self._software: Dict[str, Dict[str, Any]] = {}
        self._mitigations: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    async def load_data(self, data_dir: Optional[str] = None):
        if self._loaded and not settings.DEBUG:
            return
        if data_dir is None:
            data_dir = str(Path(__file__).parent.parent.parent / "data" / "mitre")
        data_path = Path(data_dir)
        if not data_path.exists():
            logger.warning(f"MITRE ATT&CK data directory not found: {data_dir}")
            self._loaded = True
            return
        for filename, storage in [
            ("techniques.json", self._techniques),
            ("tactics.json", self._tactics),
            ("groups.json", self._groups),
            ("software.json", self._software),
            ("mitigations.json", self._mitigations),
        ]:
            filepath = data_path / filename
            if filepath.exists():
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    storage.clear()
                    if isinstance(data, list):
                        for item in data:
                            item_id = item.get("id", "")
                            storage[item_id] = item
                    elif isinstance(data, dict):
                        storage.update(data)
                    logger.info(f"Loaded {len(storage)} entries from {filename}")
                except Exception as e:
                    logger.error(f"Failed to load {filename}: {e}")
        self._loaded = True

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        return self._techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> Optional[Dict[str, Any]]:
        return self._tactics.get(tactic_id)

    def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        query_lower = query.lower()
        results = []
        for tech_id, tech in self._techniques.items():
            name = tech.get("name", "").lower()
            description = tech.get("description", "").lower()
            if query_lower in name or query_lower in description or query_lower in tech_id.lower():
                results.append(tech)
        return results

    def get_techniques_by_tactic(self, tactic_id: str) -> List[Dict[str, Any]]:
        results = []
        for tech_id, tech in self._techniques.items():
            tactics = tech.get("tactics", [])
            if any(t.get("id") == tactic_id or t.get("name", "").lower().replace(" ", "-") == tactic_id.lower() for t in tactics):
                results.append(tech)
        return results

    def get_groups_using_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        results = []
        for group_id, group in self._groups.items():
            techniques = group.get("techniques", [])
            if any(t.get("id") == technique_id for t in techniques):
                results.append(group)
        return results

    def get_mitigations_for_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        results = []
        for mit_id, mit in self._mitigations.items():
            techniques = mit.get("techniques", [])
            if any(t.get("id") == technique_id for t in techniques):
                results.append(mit)
        return results

    def get_all_techniques(self) -> Dict[str, Dict[str, Any]]:
        return self._techniques

    def get_all_tactics(self) -> Dict[str, Dict[str, Any]]:
        return self._tactics

    def map_incident_to_techniques(self, incident_data: Dict[str, Any]) -> List[str]:
        mapped = []
        description = incident_data.get("description", "").lower()
        title = incident_data.get("title", "").lower()
        indicators = [i.lower() for i in incident_data.get("indicators", [])]
        combined_text = f"{title} {description} {' '.join(indicators)}"
        for tech_id, tech in self._techniques.items():
            tech_name = tech.get("name", "").lower()
            tech_desc = tech.get("description", "").lower()
            keywords = tech.get("keywords", [])
            if any(k.lower() in combined_text for k in keywords):
                mapped.append(tech_id)
            elif tech_name in combined_text:
                mapped.append(tech_id)
            elif any(kw in combined_text for kw in keywords):
                mapped.append(tech_id)
        return mapped

    def get_attack_lifecycle_coverage(self, mapped_techniques: List[str]) -> Dict[str, bool]:
        lifecycle = {
            "initial_access": False,
            "execution": False,
            "persistence": False,
            "privilege_escalation": False,
            "defense_evasion": False,
            "credential_access": False,
            "discovery": False,
            "lateral_movement": False,
            "collection": False,
            "command_and_control": False,
            "exfiltration": False,
            "impact": False,
        }
        for tech_id in mapped_techniques:
            tech = self._techniques.get(tech_id)
            if tech:
                for tactic_entry in tech.get("tactics", []):
                    tactic_name = tactic_entry.get("name", "").lower().replace(" ", "_")
                    if tactic_name in lifecycle:
                        lifecycle[tactic_name] = True
        return lifecycle

    def generate_remediation_plan(self, mapped_techniques: List[str]) -> List[str]:
        recommendations = []
        seen = set()
        for tech_id in mapped_techniques:
            mitigations = self.get_mitigations_for_technique(tech_id)
            for mit in mitigations:
                mit_name = mit.get("name")
                mit_desc = mit.get("description", "")
                if mit_name and mit_name not in seen:
                    seen.add(mit_name)
                    recommendations.append(f"{mit_name}: {mit_desc[:200]}")
            tech = self._techniques.get(tech_id)
            if tech:
                detection = tech.get("detection", "")
                if detection and tech_id not in seen:
                    seen.add(tech_id)
                    recommendations.append(f"Detection for {tech.get('name', tech_id)}: {detection[:200]}")
        return recommendations


mitre_manager = MITREAttackManager()
