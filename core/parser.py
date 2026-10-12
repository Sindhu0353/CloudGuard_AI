import json
from typing import Tuple, Dict, Any, Optional

class JSONParser:
    """Parses raw cloud configuration JSON files and auto-detects input formats."""

    FORMAT_CLOUDFORMATION = "cloudformation"
    FORMAT_GENERIC = "generic"
    FORMAT_UNKNOWN = "unknown"

    @staticmethod
    def parse_json_string(raw_content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Parses a raw JSON string. Returns (data_dict, error_message)."""
        if not raw_content or not raw_content.strip():
            return None, "File content is empty."
        try:
            data = json.loads(raw_content)
            if not isinstance(data, dict):
                return None, "Root JSON element must be an object (dictionary)."
            return data, None
        except json.JSONDecodeError as err:
            return None, f"Invalid JSON syntax: {str(err)}"

    @classmethod
    def detect_format(cls, data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Detects format: 'cloudformation', 'generic', or 'unknown'.
        Returns (format_type, explanation_message).
        """
        if not isinstance(data, dict):
            return cls.FORMAT_UNKNOWN, "Root object is not a JSON dictionary."

        # Check AWS CloudFormation characteristics
        is_cfn = False
        if "AWSTemplateFormatVersion" in data or "Resources" in data:
            if "Resources" in data and isinstance(data["Resources"], dict):
                is_cfn = True

        # Check Generic Cloud resource characteristics
        is_generic = False
        if "resources" in data and isinstance(data["resources"], (list, dict)):
            is_generic = True
        elif "items" in data and isinstance(data["items"], list):
            is_generic = True

        if is_cfn and not is_generic:
            return cls.FORMAT_CLOUDFORMATION, "Detected AWS CloudFormation JSON template."
        elif is_generic and not is_cfn:
            return cls.FORMAT_GENERIC, "Detected Generic Cloud Resource JSON structure."
        elif is_cfn and is_generic:
            return cls.FORMAT_CLOUDFORMATION, "Ambiguous structure; prioritizing AWS CloudFormation format."
        else:
            return cls.FORMAT_UNKNOWN, "Unrecognized template structure. Expected 'Resources' dict (CloudFormation) or 'resources' list (Generic format)."