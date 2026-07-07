import json
import os
import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from app.core.logger import logger
from app.core.config import settings


class MITREAttackAPI:
    def __init__(self, base_url: str = "https://raw.githubusercontent.com/mitre/cti/master/"):
        self.base_url = base_url
        self.cache: Dict[str, Any] = {}
        self.cache_ttl = timedelta(hours=24)

    async def fetch_techniques(self) -> List[Dict[str, Any]]:
        cache_key = "mitre_techniques"
        if cache_key in self.cache:
            return self.cache[cache_key]
        url = f"{self.base_url}enterprise-attack/enterprise-attack.json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        techniques = [
                            obj for obj in data.get("objects", [])
                            if obj.get("type") == "attack-pattern"
                        ]
                        self.cache[cache_key] = techniques
                        logger.info("Fetched %d MITRE techniques", len(techniques))
                        return techniques
        except Exception as e:
            logger.warning("Failed to fetch MITRE techniques: %s", str(e))
        return self.cache.get(cache_key, [])

    async def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        techniques = await self.fetch_techniques()
        for t in techniques:
            if t.get("id") == technique_id or t.get("external_references", [{}])[0].get("external_id") == technique_id:
                return {
                    "id": t.get("id"),
                    "technique_id": next((ref.get("external_id") for ref in t.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None),
                    "name": t.get("name"),
                    "description": t.get("description"),
                    "tactics": [phase.get("phase_name") for phase in t.get("kill_chain_phases", [])],
                    "platforms": t.get("x_mitre_platforms", []),
                    "permissions_required": t.get("x_mitre_permissions_required", []),
                    "detection": t.get("x_mitre_detection"),
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                }
        return None

    async def map_to_technique(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        description = (event.get("description") or "").lower()
        title = (event.get("title") or "").lower()
        techniques = await self.fetch_techniques()
        best_match = None
        best_score = 0
        for t in techniques:
            t_name = (t.get("name") or "").lower()
            t_desc = (t.get("description") or "").lower()
            score = 0
            for term in [t_name] + [p.get("phase_name", "") for p in t.get("kill_chain_phases", [])]:
                if term and (term in description or term in title):
                    score += 1
            if score > best_score:
                best_score = score
                best_match = t
        if best_match and best_score > 0:
            return await self.get_technique(best_match.get("id"))
        return None


class CISAKEV:
    def __init__(self, url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"):
        self.url = url
        self.cache: List[Dict[str, Any]] = []
        self.last_fetched: Optional[datetime] = None

    async def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        if self.cache and self.last_fetched and datetime.utcnow() - self.last_fetched < timedelta(hours=6):
            return self.cache
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.cache = data.get("vulnerabilities", [])
                        self.last_fetched = datetime.utcnow()
                        logger.info("Fetched %d CISA KEV entries", len(self.cache))
        except Exception as e:
            logger.warning("Failed to fetch CISA KEV: %s", str(e))
        return self.cache

    async def check_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        vulns = await self.fetch_vulnerabilities()
        for v in vulns:
            if v.get("cveID", "").upper() == cve_id.upper():
                return {
                    "cve_id": v.get("cveID"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "vulnerability_name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "short_description": v.get("shortDescription"),
                    "required_action": v.get("requiredAction"),
                    "due_date": v.get("dueDate"),
                    "known_ransomware_campaign": v.get("knownRansomwareCampaignUse"),
                    "source": "CISA KEV"
                }
        return None

    def is_known_exploited(self, cve_id: str) -> bool:
        return any(v.get("cveID", "").upper() == cve_id.upper() for v in self.cache)


class CVEDatabase:
    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache: Dict[str, Dict[str, Any]] = {}

    async def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        if cve_id in self.cache:
            return self.cache[cve_id]
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.nvd_base_url}?cveId={cve_id}", timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        if vulnerabilities:
                            cve_data = vulnerabilities[0].get("cve", {})
                            metrics = cve_data.get("metrics", {})
                            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV30") else {}
                            result = {
                                "cve_id": cve_id,
                                "source": "NVD",
                                "published": cve_data.get("published"),
                                "last_modified": cve_data.get("lastModified"),
                                "description": next((d.get("value") for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), ""),
                                "severity": (cvss_v31 or cvss_v30).get("baseSeverity", "UNKNOWN"),
                                "base_score": (cvss_v31 or cvss_v30).get("baseScore", 0),
                                "vector_string": (cvss_v31 or cvss_v30).get("vectorString", ""),
                                "attack_vector": (cvss_v31 or cvss_v30).get("attackVector", ""),
                                "impact_score": (metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}).get("impactScore", 0),
                                "exploitability_score": (metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}).get("exploitabilityScore", 0),
                                "weaknesses": [w.get("description", [{}])[0].get("value") for w in cve_data.get("weaknesses", []) if w.get("description")],
                            }
                            self.cache[cve_id] = result
                            return result
        except Exception as e:
            logger.warning("Failed to lookup CVE %s: %s", cve_id, str(e))
        return None


class CERTInAlert:
    def __init__(self):
        self.base_url = "https://www.cert-in.org.in"
        self._alerts: List[Dict[str, Any]] = []

    async def fetch_alerts(self) -> List[Dict[str, Any]]:
        if self._alerts:
            return self._alerts
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/s2cMainServlet?pageid=ALERT", timeout=30) as resp:
                    if resp.status == 200:
                        logger.info("Fetched CERT-In alerts")
        except Exception as e:
            logger.warning("CERT-In fetch failed (air-gapped): %s", str(e))
        return self._alerts

    async def relate_to_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None


class ThreatIntelService:
    def __init__(self):
        self.mitre = MITREAttackAPI()
        self.cisa_kev = CISAKEV()
        self.cve_db = CVEDatabase()
        self.cert_in = CERTInAlert()
        self._local_indicators: Dict[str, List[Dict[str, Any]]] = {
            "ip": [], "domain": [], "url": [], "hash": [], "email": []
        }

    async def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        enrichments = {}
        mitre_technique = await self.mitre.map_to_technique(event)
        if mitre_technique:
            enrichments["mitre_attack"] = mitre_technique

        indicators = event.get("indicators", []) or self._extract_indicators(event)
        for ioc in indicators:
            ioc_type = ioc.get("type", "").lower()
            ioc_value = ioc.get("value", "")
            if ioc_type == "cve":
                cve_info = await self.cve_db.lookup(ioc_value)
                if cve_info:
                    enrichments.setdefault("cve_details", []).append(cve_info)
                kev_info = await self.cisa_kev.check_cve(ioc_value)
                if kev_info:
                    enrichments.setdefault("kev_details", []).append(kev_info)

        if self._check_local_indicators(event):
            enrichments["matched_local_ioc"] = True

        return enrichments

    def _extract_indicators(self, event: Dict[str, Any]) -> List[Dict[str, str]]:
        indicators = []
        text = json.dumps(event, default=str)
        import re
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        for match in re.finditer(cve_pattern, text, re.IGNORECASE):
            indicators.append({"type": "cve", "value": match.group().upper()})
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for match in re.finditer(ip_pattern, text):
            indicators.append({"type": "ip", "value": match.group()})
        return indicators

    def load_iocs(self, ioc_type: str, iocs: List[str]):
        if ioc_type in self._local_indicators:
            self._local_indicators[ioc_type] = [
                {"value": i, "added": datetime.utcnow().isoformat()} for i in iocs
            ]
            logger.info("Loaded %d %s IOCs", len(iocs), ioc_type)

    def add_ioc(self, ioc_type: str, value: str, metadata: Dict[str, Any] = None):
        if ioc_type in self._local_indicators:
            self._local_indicators[ioc_type].append({
                "value": value, "added": datetime.utcnow().isoformat(), "metadata": metadata or {}
            })

    def _check_local_indicators(self, event: Dict[str, Any]) -> bool:
        raw = json.dumps(event, default=str).lower()
        for ioc_type, iocs in self._local_indicators.items():
            for ioc in iocs:
                if ioc["value"].lower() in raw:
                    return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "local_iocs": {k: len(v) for k, v in self._local_indicators.items()},
            "cisa_kev_cached": len(self.cisa_kev.cache),
            "cve_cache_size": len(self.cve_db.cache)
        }


threat_intel = ThreatIntelService()
