import http.server
import socketserver
import json
import os
import urllib.parse
from typing import Dict, Any

from core.scanner import CloudScanner
from core.risk_engine import RiskEngine
from core.remediation import RemediationSimulator
from core.database import DatabaseManager
from core.reports import ReportGenerator

PORT = int(os.environ.get("PORT", 8000))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

scanner = CloudScanner()
db_manager = DatabaseManager()
remediator = RemediationSimulator(scanner=scanner)
report_gen = ReportGenerator()

class CloudGuardRequestHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def _send_json(self, data: Dict[str, Any], status_code: int = 200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/api/history":
            history = db_manager.get_history(limit=10)
            self._send_json({"success": True, "history": history})
            return

        elif path == "/api/baseline":
            if scanner.baseline_manager.load_error:
                self._send_json({
                    "success": False,
                    "error": scanner.baseline_manager.load_error
                }, status_code=500)
            else:
                self._send_json({
                    "success": True,
                    "metadata": scanner.baseline_manager.get_metadata(),
                    "rules": scanner.baseline_manager.get_all_rules()
                })
            return

        elif path.startswith("/api/scan/"):
            try:
                scan_id = int(path.split("/")[-1])
                scan_data = db_manager.get_scan_details(scan_id)
                if scan_data:
                    self._send_json({"success": True, "scan": scan_data})
                else:
                    self._send_json({"success": False, "error": "Scan ID not found"}, status_code=404)
            except ValueError:
                self._send_json({"success": False, "error": "Invalid Scan ID"}, status_code=400)
            return

        elif path.startswith("/api/report/"):
            parts = path.split("/")
            if len(parts) >= 4:
                rpt_type = parts[2]
                try:
                    scan_id = int(parts[3])
                    scan_data = db_manager.get_scan_details(scan_id)
                    if not scan_data:
                        self._send_json({"success": False, "error": "Scan not found"}, status_code=404)
                        return

                    filepath = report_gen.generate_json_report(scan_id, scan_data) if rpt_type == "json" else report_gen.generate_html_report(scan_id, scan_data)

                    if os.path.exists(filepath):
                        self.send_response(200)
                        mime = "application/json" if rpt_type == "json" else "text/html"
                        self.send_header("Content-Type", mime)
                        self.send_header("Content-Disposition", f"attachment; filename={os.path.basename(filepath)}")
                        self.end_headers()
                        with open(filepath, "rb") as f:
                            self.wfile.write(f.read())
                        return
                except ValueError:
                    pass
            self._send_json({"success": False, "error": "Invalid report request"}, status_code=400)
            return

        super().do_GET()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if path == "/api/scan":
            try:
                payload = json.loads(body)
                filename = payload.get("filename", "uploaded_template.json")
                raw_json = payload.get("content", "")

                scan_result = scanner.scan(raw_json)
                if not scan_result["success"]:
                    self._send_json(scan_result, status_code=400)
                    return

                raw_findings = scan_result["findings"]
                prioritized_findings, summary_counts, overall_risk = RiskEngine.prioritize_findings(raw_findings)

                response_payload = {
                    "success": True,
                    "filename": filename,
                    "format": scan_result["format"],
                    "format_description": scan_result["format_description"],
                    "resources_analyzed": scan_result["resources_analyzed"],
                    "total_findings": len(prioritized_findings),
                    "overall_risk_score": overall_risk,
                    "summary_counts": summary_counts,
                    "findings": prioritized_findings,
                    "raw_data": scan_result["raw_data"]
                }

                scan_id = db_manager.save_scan(filename, response_payload, raw_json)
                response_payload["scan_id"] = scan_id

                self._send_json(response_payload)
            except json.JSONDecodeError:
                self._send_json({"success": False, "error": "Invalid JSON body payload"}, status_code=400)
            return

        elif path == "/api/remediate":
            try:
                payload = json.loads(body)
                scan_id = payload.get("scan_id")
                rule_id = payload.get("rule_id")
                resource_id = payload.get("resource_id")
                raw_data = payload.get("raw_data")
                fmt_type = payload.get("format")

                if not all([rule_id, resource_id, raw_data, fmt_type]):
                    self._send_json({"success": False, "error": "Missing required parameters"}, status_code=400)
                    return

                remediated_data, modified, msg = remediator.simulate_remediation(raw_data, rule_id, resource_id, fmt_type)
                remediated_json_str = json.dumps(remediated_data)
                rescan_result = scanner.scan(remediated_json_str)
                rescan_findings, rescan_counts, rescan_risk = RiskEngine.prioritize_findings(rescan_result.get("findings", []))

                db_manager.log_remediation(scan_id or 0, rule_id, resource_id, "SUCCESS" if modified else "NO_CHANGE", msg)

                self._send_json({
                    "success": True,
                    "message": msg,
                    "modified": modified,
                    "remediated_data": remediated_data,
                    "remediated_json_str": remediated_json_str,
                    "after_scan": {
                        "total_findings": len(rescan_findings),
                        "overall_risk_score": rescan_risk,
                        "summary_counts": rescan_counts,
                        "findings": rescan_findings
                    }
                })
            except Exception as err:
                self._send_json({"success": False, "error": str(err)}, status_code=500)
            return

        self._send_json({"success": False, "error": "Endpoint not found"}, status_code=404)


# WSGI Adaptor Callable for Serverless execution (Vercel)
from io import BytesIO

def app(environ, start_response):
    class WSGIRequestWrapper:
        def __init__(self, environ):
            self.environ = environ
            self.rfile = environ['wsgi.input']
            self.wfile = BytesIO()
            self.headers = {
                'Content-Length': environ.get('CONTENT_LENGTH', '0'),
                'Content-Type': environ.get('CONTENT_TYPE', '')
            }
            self.command = environ['REQUEST_METHOD']
            self.path = environ.get('PATH_INFO', '')
            if environ.get('QUERY_STRING'):
                self.path += '?' + environ['QUERY_STRING']
            self.request_version = 'HTTP/1.1'
            self.status_code = 200
            self.response_headers = []

        def send_response(self, code, message=None):
            self.status_code = code

        def send_header(self, keyword, value):
            self.response_headers.append((keyword, value))

        def end_headers(self):
            pass

    req = WSGIRequestWrapper(environ)
    handler = CloudGuardRequestHandler.__new__(CloudGuardRequestHandler)
    handler.rfile = req.rfile
    handler.wfile = req.wfile
    handler.headers = req.headers
    handler.command = req.command
    handler.path = req.path
    handler.request_version = req.request_version
    handler.send_response = req.send_response
    handler.send_header = req.send_header
    handler.end_headers = req.end_headers

    if req.command == 'GET':
        handler.do_GET()
    elif req.command == 'POST':
        handler.do_POST()
    elif req.command == 'OPTIONS':
        handler.do_OPTIONS()

    status_str = f"{req.status_code} OK" if req.status_code == 200 else f"{req.status_code} Error"
    start_response(status_str, req.response_headers)
    return [req.wfile.getvalue()]


def run_server():
    os.chdir(WEB_DIR)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), CloudGuardRequestHandler) as httpd:
        print(f"CloudGuard AI Server initialized at http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")

if __name__ == "__main__":
    run_server()