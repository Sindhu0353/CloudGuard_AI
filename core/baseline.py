import json
import os
from typing import Dict, Any, List, Optional, Tuple

class BaselineManager:
    """Loads, validates, and manages security baseline rules and metadata."""

    def __init__(self, baseline_path: str = None):
        if baseline_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            baseline_path = os.path.join(base_dir, "config", "security_baseline.json")
        self.baseline_path = baseline_path
        self.rules: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.load_error: Optional[str] = None
        self.load_baseline()

    def load_baseline(self) -> Tuple[bool, Optional[str]]:
        """Loads and validates baseline rules from JSON configuration file."""
        self.load_error = None
        if not os.path.exists(self.baseline_path):
            self.load_error = f"Baseline file not found at path: {self.baseline_path}"
            return False, self.load_error

        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                self.load_error = "Invalid baseline format: Root JSON element must be an object."
                return False, self.load_error

            self.metadata = {
                "version": data.get("version", "1.0.0"),
                "description": data.get("description", ""),
                "framework_references": data.get("metadata", {}).get("framework_references", [])
            }
            raw_rules = data.get("rules", [])
            if not isinstance(raw_rules, list):
                self.load_error = "Invalid baseline format: 'rules' property must be an array."
                return False, self.load_error

            valid_rules = []
            for idx, r in enumerate(raw_rules):
                if isinstance(r, dict) and "id" in r and "applicable_types" in r and "severity" in r:
                    valid_rules.append(r)
                else:
                    print(f"Warning: Baseline rule at index {idx} skipped due to missing required fields.")

            self.rules = valid_rules
            return True, None

        except json.JSONDecodeError as err:
            self.load_error = f"Malformed JSON syntax in baseline file: {str(err)}"
            return False, self.load_error
        except Exception as err:
            self.load_error = f"Error reading baseline file: {str(err)}"
            return False, self.load_error

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Returns all validated baseline rules."""
        return self.rules

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific baseline rule by its unique identifier."""
        for rule in self.rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_metadata(self) -> Dict[str, Any]:
        """Returns baseline version and methodology source metadata."""
        return self.metadata

    def get_rules_for_type(self, resource_type: str) -> List[Dict[str, Any]]:
        """Filters baseline rules matching a target cloud resource type."""
        matching_rules = []
        for rule in self.rules:
            applicable = rule.get("applicable_types", [])
            if resource_type in applicable or "*" in applicable:
                matching_rules.append(rule)
        return matching_rules