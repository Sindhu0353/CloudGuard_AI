from typing import Dict, Any, List, Tuple
from core.parser import JSONParser

class InputValidator:
    """Validates structural and schema integrity of parsed cloud JSON inputs."""

    @staticmethod
    def validate_structure(data: Dict[str, Any], format_type: str) -> Tuple[bool, List[str]]:
        """
        Validates structure for the given detected format.
        Returns (is_valid, list_of_validation_errors).
        """
        errors = []

        if format_type == JSONParser.FORMAT_CLOUDFORMATION:
            if "Resources" not in data:
                errors.append("CloudFormation template missing top-level 'Resources' property.")
            elif not isinstance(data["Resources"], dict):
                errors.append("'Resources' property must be a JSON object containing logical resource definitions.")
            elif len(data["Resources"]) == 0:
                errors.append("'Resources' object is empty. No resources available to scan.")
            else:
                for res_id, res_val in data["Resources"].items():
                    if not isinstance(res_val, dict):
                        errors.append(f"Resource '{res_id}' must be an object.")
                        continue
                    if "Type" not in res_val:
                        errors.append(f"Resource '{res_id}' is missing required 'Type' field.")

        elif format_type == JSONParser.FORMAT_GENERIC:
            resources = data.get("resources") or data.get("items")
            if resources is None:
                errors.append("Generic template missing top-level 'resources' list or object.")
            elif isinstance(resources, list):
                if len(resources) == 0:
                    errors.append("'resources' list is empty.")
                for idx, res in enumerate(resources):
                    if not isinstance(res, dict):
                        errors.append(f"Resource at index {idx} must be an object.")
                        continue
                    if "id" not in res and "resource_id" not in res:
                        errors.append(f"Resource at index {idx} missing 'id' or 'resource_id'.")
                    if "type" not in res and "resource_type" not in res:
                        errors.append(f"Resource at index {idx} missing 'type' or 'resource_type'.")
            elif isinstance(resources, dict):
                if len(resources) == 0:
                    errors.append("'resources' object is empty.")
                for res_id, res in resources.items():
                    if not isinstance(res, dict):
                        errors.append(f"Resource '{res_id}' must be an object.")
                        continue
                    if "type" not in res and "resource_type" not in res:
                        errors.append(f"Resource '{res_id}' missing 'type' or 'resource_type'.")
            else:
                errors.append("'resources' property must be a list or dictionary.")

        else:
            errors.append("Unsupported template format. Provide valid CloudFormation or Generic Cloud JSON.")

        return len(errors) == 0, errors