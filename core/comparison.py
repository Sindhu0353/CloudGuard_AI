from typing import Dict, Any, List, Optional

class ComparisonEngine:
    """Evaluates extracted resource configurations against security baseline controls."""

    @staticmethod
    def evaluate_rule(resource_id: str, resource_type: str, properties: Dict[str, Any], rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates a single rule against a resource property configuration.
        Returns finding dict if misconfigured, or None if safe.
        """
        prop_path = rule.get("property_path")
        check_type = rule.get("check_type", "disallowed_value")
        
        # Traverse properties dict
        curr_val = properties
        path_parts = prop_path.split(".") if prop_path else []
        found = True
        
        for part in path_parts:
            if isinstance(curr_val, dict) and part in curr_val:
                curr_val = curr_val[part]
            else:
                found = False
                break

        is_violation = False
        observed_val_str = ""

        # 1. Check for missing required security property
        if check_type == "presence":
            if not found or curr_val is None:
                is_violation = True
                observed_val_str = "Property missing or null"

        # 2. Check for boolean true requirement
        elif check_type == "boolean_true":
            if not found or str(curr_val).lower() not in ["true", "1", "enabled"]:
                is_violation = True
                observed_val_str = str(curr_val) if found else "Not Configured / Disabled"

        # 3. Check for open security group ports (0.0.0.0/0)
        elif check_type == "open_port":
            target_port = rule.get("target_port")
            disallowed_cidr = rule.get("disallowed_cidr", "0.0.0.0/0")
            
            ingress_rules = curr_val if (found and isinstance(curr_val, list)) else []
            for ingress in ingress_rules:
                if isinstance(ingress, dict):
                    from_port = ingress.get("FromPort") or ingress.get("from_port") or ingress.get("port")
                    to_port = ingress.get("ToPort") or ingress.get("to_port") or ingress.get("port")
                    cidr = ingress.get("CidrIp") or ingress.get("cidr_ip") or ingress.get("source")
                    
                    port_matches = False
                    if from_port is not None and to_port is not None:
                        if int(from_port) <= target_port <= int(to_port):
                            port_matches = True
                    
                    if port_matches and cidr == disallowed_cidr:
                        is_violation = True
                        observed_val_str = f"Port {target_port} open to {disallowed_cidr}"
                        break

        # 4. Check IAM wildcard policy permissions
        elif check_type == "iam_wildcard":
            if found and isinstance(curr_val, dict):
                statements = curr_val.get("Statement") or curr_val.get("statements") or []
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                        action = stmt.get("Action")
                        resource = stmt.get("Resource")
                        if (action == "*" or action == ["*"]) and (resource == "*" or resource == ["*"]):
                            is_violation = True
                            observed_val_str = "Statement allows Action: '*' on Resource: '*'"
                            break

        # 5. Check disallowed exact values
        else:
            disallowed = rule.get("disallowed_values", [])
            if found and curr_val in disallowed:
                is_violation = True
                observed_val_str = str(curr_val)

        if is_violation:
            return {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "resource_id": resource_id,
                "resource_type": resource_type,
                "severity": rule["severity"],
                "observed_value": observed_val_str,
                "expected_state": rule.get("expected_state", ""),
                "explanation": rule.get("explanation", ""),
                "remediation": rule.get("remediation", "")
            }

        return None