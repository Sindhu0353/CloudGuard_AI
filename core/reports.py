import json
import os
from typing import Dict, Any

class ReportGenerator:
    """Generates downloadable JSON and HTML security report files."""

    def __init__(self, output_dir: str = None):
        if output_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            output_dir = os.path.join(base_dir, "reports")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json_report(self, scan_id: int, scan_data: Dict[str, Any]) -> str:
        """Saves scan data as a formatted JSON report."""
        filename = f"scan_report_{scan_id}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2)
        return filepath

    def generate_html_report(self, scan_id: int, scan_data: Dict[str, Any]) -> str:
        """Generates a standalone, CSS-styled HTML audit report."""
        filename = f"scan_report_{scan_id}.html"
        filepath = os.path.join(self.output_dir, filename)

        findings = scan_data.get("findings", [])
        findings_rows = ""
        for f in findings:
            sev_class = f.get("risk_category", "Low").lower()
            findings_rows += f"""
            <tr class="severity-{sev_class}">
                <td><strong>{f.get('resource_id')}</strong><br><small>{f.get('resource_type')}</small></td>
                <td><strong>{f.get('rule_id')}</strong><br>{f.get('rule_name')}</td>
                <td><span class="badge badge-{sev_class}">{f.get('risk_category')} ({f.get('risk_score')})</span></td>
                <td><code>{f.get('observed_value')}</code></td>
                <td>{f.get('explanation')}</td>
                <td>{f.get('remediation')}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = "<tr><td colspan='6' style='text-align:center; padding: 20px; color: #28a745;'><strong>No security misconfigurations detected! Baseline verified.</strong></td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CloudGuard AI - Security Report #{scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155; }}
        h1 {{ color: #38bdf8; margin-top: 0; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .metrics {{ display: flex; gap: 20px; margin: 25px 0; }}
        .card {{ flex: 1; background: #0f172a; padding: 15px 20px; border-radius: 8px; border: 1px solid #334155; text-align: center; }}
        .card h3 {{ margin: 0; color: #94a3b8; font-size: 14px; text-transform: uppercase; }}
        .card p {{ margin: 8px 0 0; font-size: 28px; font-weight: bold; color: #f8fafc; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        code {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #f43f5e; font-family: monospace; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: #881337; color: #fecdd3; }}
        .badge-high {{ background: #7c2d12; color: #ffedd5; }}
        .badge-medium {{ background: #713f12; color: #fef08a; }}
        .badge-low {{ background: #14532d; color: #bbf7d0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CloudGuard AI Security Audit Report</h1>
        <p><strong>Scan ID:</strong> #{scan_id} | <strong>File:</strong> {scan_data.get('filename')} | <strong>Format:</strong> {scan_data.get('format')}</p>
        
        <div class="metrics">
            <div class="card"><h3>Resources Analyzed</h3><p>{scan_data.get('resources_analyzed')}</p></div>
            <div class="card"><h3>Total Findings</h3><p>{scan_data.get('total_findings')}</p></div>
            <div class="card"><h3>Overall Risk Score</h3><p>{scan_data.get('overall_risk_score')} / 100</p></div>
        </div>

        <h2>Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Resource</th>
                    <th>Rule Violation</th>
                    <th>Risk Rating</th>
                    <th>Observed State</th>
                    <th>Explanation</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath