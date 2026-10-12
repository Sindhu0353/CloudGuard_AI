import copy
import json
from typing import Dict, Any, Tuple
from core.scanner import CloudScanner
from core.risk_engine import RiskEngine

class RemediationSimulator:
    """Safe, non-destructive remediation simulation on cloned configuration dictionaries."""

    def __init__(self, scanner: CloudScanner = None):
        self.scanner = scanner or CloudScanner()

    def simulate_remediation(self, original_data: Dict[str, Any], rule_id: str, resource_id: str, format_type: str) -> Tuple[Dict[str, Any], bool, str]:
        """
        Modifies ONLY a deep copy of the configuration data.
        Returns (remediated_data, success_flag, message).
        """
        data_copy = copy.deepcopy(original_data)
        modified = False
        msg = ""

        if format_type == "cloudformation":
            resources = data_copy.get("Resources", {})
            if resource_id in resources:
                res = resources[resource_id]
                props = res.setdefault("Properties", {})

                if rule_id == "CG-AWS-S3-001":
                    props["AccessControl"] = "Private"
                    modified = True
                    msg = f"Set 'AccessControl' to 'Private' on {resource_id}."

                elif rule_id == "CG-AWS-S3-002":
                    props["BucketEncryption"] = {
                        "ServerSideEncryptionConfiguration": [
                            {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                        ]
                    }
                    modified = True
                    msg = f"Added default SSE-S3 BucketEncryption to {resource_id}."

                elif rule_id == "CG-AWS-EC2-001":
                    ingress_rules = props.get("SecurityGroupIngress", [])
                    new_ingress = []
                    for ing in ingress_rules:
                        if isinstance(ing, dict):
                            c_ip = ing.get("CidrIp") or ing.get("cidr_ip")
                            if c_ip == "0.0.0.0/0":
                                ing["CidrIp"] = "10.0.0.0/8" # Restrict to internal CIDR
                    props["SecurityGroupIngress"] = ingress_rules
                    modified = True
                    msg = f"Restricted SSH CIDR from 0.0.0.0/0 to 10.0.0.0/8 on {resource_id}."

                elif rule_id == "CG-AWS-IAM-001":
                    p_doc = props.get("PolicyDocument", {})
                    stmts = p_doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for s in stmts:
                        if isinstance(s, dict) and s.get("Effect") == "Allow":
                            if s.get("Action") in ["*", ["*"]]:
                                s["Action"] = ["s3:GetObject", "s3:ListBucket"]
                    p_doc["Statement"] = stmts
                    props["PolicyDocument"] = p_doc
                    modified = True
                    msg = f"Replaced wildcard Action '*' with specific read permissions on {resource_id}."

                elif rule_id == "CG-AWS-RDS-001":
                    props["PubliclyAccessible"] = False
                    modified = True
                    msg = f"Set 'PubliclyAccessible' to false on {resource_id}."

                elif rule_id == "CG-GEN-LOG-001":
                    props["LoggingEnabled"] = True
                    modified = True
                    msg = f"Enabled 'LoggingEnabled' flag on {resource_id}."

        elif format_type == "generic":
            resources = data_copy.get("resources") or data_copy.get("items") or []
            target_res = None
            if isinstance(resources, list):
                for r in resources:
                    if isinstance(r, dict) and (r.get("id") == resource_id or r.get("resource_id") == resource_id):
                        target_res = r
                        break
            elif isinstance(resources, dict) and resource_id in resources:
                target_res = resources[resource_id]

            if target_res:
                props = target_res.setdefault("properties", target_res.setdefault("configuration", {}))
                
                if rule_id == "CG-AWS-S3-001":
                    props["access_control"] = "private"
                    props["AccessControl"] = "Private"
                    modified = True
                    msg = f"Updated access control to private on {resource_id}."
                elif rule_id == "CG-AWS-S3-002":
                    props["encryption"] = {"enabled": True, "type": "AES256"}
                    props["BucketEncryption"] = {"enabled": True}
                    modified = True
                    msg = f"Enabled encryption on {resource_id}."
                elif rule_id == "CG-GEN-LOG-001":
                    props["logging_enabled"] = True
                    props["LoggingEnabled"] = True
                    modified = True
                    msg = f"Enabled access logging on {resource_id}."

        if not modified:
            msg = f"No automated simulation handler found for rule {rule_id} on {resource_id}."

        return data_copy, modified, msg