from typing import Dict, Any, List, Tuple
from core.parser import JSONParser
from core.validator import InputValidator
from core.baseline import BaselineManager
from core.comparison import ComparisonEngine

class CloudScanner:
    """Extracts cloud resources and evaluates them against active baseline rules."""

    def __init__(self, baseline_manager: BaselineManager = None):
        self.baseline_manager = baseline_manager or BaselineManager()

    def extract_resources(self, data: Dict[str, Any], format_type: str) -> List[Tuple[str, str, Dict[str, Any], int]]:
        """
        Extracts resources in standardized tuples: (resource_id, resource_type, properties, asset_importance)
        """
        extracted = []

        if format_type == JSONParser.FORMAT_CLOUDFORMATION:
            resources = data.get("Resources", {})
            for res_id, res_def in resources.items():
                if isinstance(res_def, dict):
                    res_type = res_def.get("Type", "Unknown")
                    props = res_def.get("Properties", {})
                    importance = res_def.get("AssetImportance", 100) # Default importance = 100
                    extracted.append((res_id, res_type, props, int(importance)))

        elif format_type == JSONParser.FORMAT_GENERIC:
            resources = data.get("resources") or data.get("items") or []
            if isinstance(resources, dict):
                for res_id, res_def in resources.items():
                    if isinstance(res_def, dict):
                        res_type = res_def.get("type") or res_def.get("resource_type", "Unknown")
                        props = res_def.get("properties") or res_def.get("configuration", {})
                        importance = res_def.get("asset_importance") or res_def.get("importance", 100)
                        extracted.append((res_id, res_type, props, int(importance)))
            elif isinstance(resources, list):
                for idx, res_def in enumerate(resources):
                    if isinstance(res_def, dict):
                        res_id = res_def.get("id") or res_def.get("resource_id", f"resource_{idx+1}")
                        res_type = res_def.get("type") or res_def.get("resource_type", "Unknown")
                        props = res_def.get("properties") or res_def.get("configuration", {})
                        importance = res_def.get("asset_importance") or res_def.get("importance", 100)
                        extracted.append((res_id, res_type, props, int(importance)))

        return extracted

    def scan(self, raw_json_str: str) -> Dict[str, Any]:
        """
        Main scan pipeline. Parses, validates, extracts, compares, and returns raw findings.
        """
        data, parse_err = JSONParser.parse_json_string(raw_json_str)
        if parse_err:
            return {
                "success": False,
                "error": parse_err,
                "format": JSONParser.FORMAT_UNKNOWN,
                "resources_analyzed": 0,
                "findings": []
            }

        fmt_type, fmt_desc = JSONParser.detect_format(data)
        is_valid, val_errors = InputValidator.validate_structure(data, fmt_type)

        if not is_valid:
            return {
                "success": False,
                "error": "; ".join(val_errors),
                "format": fmt_type,
                "resources_analyzed": 0,
                "findings": []
            }

        resources = self.extract_resources(data, fmt_type)
        findings = []

        for res_id, res_type, props, importance in resources:
            applicable_rules = self.baseline_manager.get_rules_for_type(res_type)
            for rule in applicable_rules:
                finding = ComparisonEngine.evaluate_rule(res_id, res_type, props, rule)
                if finding:
                    finding["asset_importance"] = max(1, min(100, importance))
                    findings.append(finding)

        return {
            "success": True,
            "format": fmt_type,
            "format_description": fmt_desc,
            "resources_analyzed": len(resources),
            "findings": findings,
            "raw_data": data
        }