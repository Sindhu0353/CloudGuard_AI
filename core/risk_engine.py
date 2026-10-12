from typing import Dict, Any, List, Tuple

class RiskEngine:
    """Computes transparent, deterministic risk scores and categorizes severity."""

    @staticmethod
    def calculate_risk_score(severity: int, asset_importance: int) -> float:
        """
        Calculates Risk Score = (Severity * Asset Importance) / 100.
        Normalized to 0.0 - 100.0 scale.
        """
        sev = max(0, min(100, severity))
        imp = max(0, min(100, asset_importance))
        return round((sev * imp) / 100.0, 1)

    @staticmethod
    def categorize_risk(risk_score: float) -> str:
        """Categorizes numerical risk scores into discrete risk tiers."""
        if risk_score >= 80.0:
            return "Critical"
        elif risk_score >= 60.0:
            return "High"
        elif risk_score >= 35.0:
            return "Medium"
        else:
            return "Low"

    @classmethod
    def prioritize_findings(cls, findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int], float]:
        """
        Calculates risk scores, attaches metadata, sorts findings from highest to lowest risk,
        and computes summary counts.
        """
        processed_findings = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_risk_sum = 0.0

        for f in findings:
            f_copy = dict(f)
            sev = f_copy.get("severity", 50)
            imp = f_copy.get("asset_importance", 100)
            
            score = cls.calculate_risk_score(sev, imp)
            category = cls.categorize_risk(score)
            
            f_copy["risk_score"] = score
            f_copy["risk_category"] = category
            f_copy["score_explanation"] = f"Severity ({sev}) × Asset Importance ({imp}) / 100 = {score} ({category})"
            
            counts[category.lower()] += 1
            total_risk_sum += score
            processed_findings.append(f_copy)

        # Sort descending by risk score
        processed_findings.sort(key=lambda x: x["risk_score"], reverse=True)

        overall_risk = round(total_risk_sum / len(processed_findings), 1) if processed_findings else 0.0

        return processed_findings, counts, overall_risk