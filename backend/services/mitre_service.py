"""
MITRE ATT&CK Service
Loads the offline enterprise-attack.json from backend/data/
and maps detected attack types to real MITRE technique data.
"""

import json
import os
from typing import Optional

# =========================================================
# PATH TO OFFLINE STIX BUNDLE
# =========================================================

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
ENTERPRISE_ATTACK_PATH = os.path.join(DATA_DIR, "enterprise-attack.json")

# =========================================================
# ATTACK TYPE → MITRE TECHNIQUE ID MAPPING
# Maps your classifier's output labels to ATT&CK technique IDs.
# These are stable IDs — they won't change between STIX versions.
# =========================================================

ATTACK_TYPE_TO_TECHNIQUE_ID = {
    "DoS":                "T1499",   # Endpoint Denial of Service
    "DDoS":               "T1498",   # Network Denial of Service
    "PortScan":           "T1046",   # Network Service Discovery
    "BruteForce":         "T1110",   # Brute Force
    "Exploit":            "T1203",   # Exploitation for Client Execution
    "Anomalous Behavior": "T1046",   # Network Service Discovery — generic unexplained anomaly
    # Modern attack classes — synthetic augmentation
    "C2":                 "T1071",   # Application Layer Protocol (C2 channel)
    "LateralMovement":    "T1021",   # Remote Services
    "Exfiltration":       "T1048",   # Exfiltration Over Alternative Protocol
    "WebAttack":          "T1190",   # Exploit Public-Facing Application
    "Benign":             None,
}


class MITREService:

    def __init__(self):
        self._technique_lookup = {}   # technique_id → technique dict
        self._tactic_lookup = {}      # tactic short_name → display name
        self._load_attack_data()

    # ----------------------------------------------------------
    # LOAD & INDEX
    # ----------------------------------------------------------

    def _load_attack_data(self):
        if not os.path.exists(ENTERPRISE_ATTACK_PATH):
            print(f"⚠️  enterprise-attack.json not found at: {ENTERPRISE_ATTACK_PATH}")
            print("   MITRE mapping will use fallback stubs.")
            return

        print(f"📖 Loading MITRE ATT&CK data from: {ENTERPRISE_ATTACK_PATH}")

        try:
            with open(ENTERPRISE_ATTACK_PATH, "r", encoding="utf-8") as f:
                bundle = json.load(f)

            objects = bundle.get("objects", [])

            for obj in objects:
                obj_type = obj.get("type", "")

                # Index attack-patterns (techniques)
                if obj_type == "attack-pattern" and not obj.get("revoked", False):
                    technique_id = self._extract_technique_id(obj)
                    if technique_id:
                        self._technique_lookup[technique_id] = obj

                # Index x-mitre-tactic for display names
                elif obj_type == "x-mitre-tactic":
                    short_name = obj.get("x_mitre_shortname", "")
                    display_name = obj.get("name", short_name)
                    if short_name:
                        self._tactic_lookup[short_name] = display_name

            print(f"✅ Indexed {len(self._technique_lookup)} techniques, "
                  f"{len(self._tactic_lookup)} tactics")

        except (json.JSONDecodeError, KeyError) as e:
            print(f"❌ Failed to parse enterprise-attack.json: {e}")

    def _extract_technique_id(self, obj: dict) -> Optional[str]:
        """Pull the Txxxx ID from the external_references list."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def map_attack(self, attack_type: str) -> dict:
        """
        Map a classifier attack type label to MITRE ATT&CK data.
        Returns a dict ready to be sent to the frontend.
        """
        if attack_type == "Benign":
            return {
                "technique_id": None,
                "technique_name": "No Threat",
                "tactic": "N/A",
                "tactic_display": "N/A",
                "description": "Traffic classified as normal/benign.",
                "url": None,
                "severity": "None",
                "platforms": [],
                "data_sources": [],
                "mitigations": []
            }

        technique_id = ATTACK_TYPE_TO_TECHNIQUE_ID.get(attack_type)

        if technique_id and technique_id in self._technique_lookup:
            return self._build_result(attack_type, technique_id)

        # Fallback: technique ID known but not in loaded data
        if technique_id:
            return self._fallback_result(attack_type, technique_id)

        # Unknown attack type entirely
        return self._fallback_result("Unknown Anomaly", "T0000")

    def get_all_techniques(self) -> list:
        """Return all mapped techniques for the frontend techniques panel."""
        results = []
        for attack_type, technique_id in ATTACK_TYPE_TO_TECHNIQUE_ID.items():
            if attack_type in ("Benign",):
                continue
            entry = self.map_attack(attack_type)
            entry["attack_type"] = attack_type
            results.append(entry)
        return results

    def search_techniques(self, query: str) -> list:
        """
        Search indexed techniques by name or ID.
        Useful for debugging or future frontend search features.
        """
        query_lower = query.lower()
        results = []
        for tid, obj in self._technique_lookup.items():
            name = obj.get("name", "").lower()
            if query_lower in name or query_lower in tid.lower():
                results.append(self._build_result("", tid))
        return results[:20]

    # ----------------------------------------------------------
    # INTERNAL BUILDERS
    # ----------------------------------------------------------

    def _build_result(self, attack_type: str, technique_id: str) -> dict:
        obj = self._technique_lookup[technique_id]

        name = obj.get("name", "Unknown Technique")
        description = obj.get("description", "No description available.")
        # Trim long descriptions
        if len(description) > 400:
            description = description[:400].rsplit(" ", 1)[0] + "…"

        # Tactics: kill_chain_phases list
        tactics = obj.get("kill_chain_phases", [])
        tactic_short = tactics[0].get("phase_name", "unknown") if tactics else "unknown"
        tactic_display = self._tactic_lookup.get(tactic_short, tactic_short.replace("-", " ").title())

        # Platforms
        platforms = obj.get("x_mitre_platforms", [])

        # Data sources
        data_sources = obj.get("x_mitre_data_sources", [])[:5]

        # URL
        url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"

        # Severity derived from tactic
        severity = self._tactic_to_severity(tactic_short)

        return {
            "technique_id": technique_id,
            "technique_name": name,
            "tactic": tactic_short,
            "tactic_display": tactic_display,
            "description": description,
            "url": url,
            "severity": severity,
            "platforms": platforms,
            "data_sources": data_sources,
        }

    def _fallback_result(self, attack_type: str, technique_id: str) -> dict:
        """Used when enterprise-attack.json is missing or technique not indexed."""
        fallback_map = {
            "DoS":                ("T1499", "Endpoint Denial of Service",              "impact",              "High"),
            "DDoS":               ("T1498", "Network Denial of Service",               "impact",              "High"),
            "PortScan":           ("T1046", "Network Service Discovery",               "discovery",           "Medium"),
            "BruteForce":         ("T1110", "Brute Force",                             "credential-access",   "High"),
            "Exploit":            ("T1203", "Exploitation for Client Execution",       "execution",           "Critical"),
            "Anomalous Behavior": ("T1046", "Network Service Discovery",               "discovery",           "Medium"),
            "C2":                 ("T1071", "Application Layer Protocol — C2 Channel","command-and-control", "Critical"),
            "LateralMovement":    ("T1021", "Remote Services",                        "lateral-movement",    "Critical"),
            "Exfiltration":       ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration",        "Critical"),
            "WebAttack":          ("T1190", "Exploit Public-Facing Application",      "initial-access",      "Critical"),
            "Unknown Anomaly":    ("T0000", "Unknown / Unclassified Threat",          "unknown",             "Medium"),
        }

        tid, tname, tactic, severity = fallback_map.get(
            attack_type,
            (technique_id, "Unknown Technique", "unknown", "Medium")
        )

        return {
            "technique_id": tid,
            "technique_name": tname,
            "tactic": tactic,
            "tactic_display": tactic.replace("-", " ").title(),
            "description": "Description unavailable — enterprise-attack.json not loaded.",
            "url": f"https://attack.mitre.org/techniques/{tid}",
            "severity": severity,
            "platforms": [],
            "data_sources": [],
        }

    @staticmethod
    def _tactic_to_severity(tactic_short: str) -> str:
        severity_map = {
            "initial-access":        "Critical",
            "execution":             "Critical",
            "persistence":           "High",
            "privilege-escalation":  "Critical",
            "defense-evasion":       "High",
            "credential-access":     "High",
            "discovery":             "Medium",
            "lateral-movement":      "Critical",
            "collection":            "High",
            "command-and-control":   "Critical",
            "exfiltration":          "Critical",
            "impact":                "High",
            "resource-development":  "Medium",
            "reconnaissance":        "Medium",
        }
        return severity_map.get(tactic_short, "Medium")