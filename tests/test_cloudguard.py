import unittest
import json
import os
import tempfile

from core.parser import JSONParser
from core.validator import InputValidator
from core.baseline import BaselineManager
from core.scanner import CloudScanner
from core.risk_engine import RiskEngine
from core.remediation import RemediationSimulator
from core.database import DatabaseManager

class TestCloudGuardEngine(unittest.TestCase):

    def setUp(self):
        self.baseline = BaselineManager()
        self.scanner = CloudScanner(baseline_manager=self.baseline)
        self.remediator = RemediationSimulator(scanner=self.scanner)
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(db_path=self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_baseline_loading_and_metadata(self):
        self.assertGreater(len(self.baseline.get_all_rules()), 0)
        rule = self.baseline.get_rule_by_id("CG-AWS-S3-001")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["name"], "S3 Bucket Public Read/Write Access")
        
        metadata = self.baseline.get_metadata()
        self.assertIn("framework_references", metadata)

    def test_invalid_baseline_path_handling(self):
        invalid_bm = BaselineManager(baseline_path="invalid/path/to/baseline.json")
        self.assertIsNotNone(invalid_bm.load_error)
        self.assertIn("Baseline file not found", invalid_bm.load_error)

    def test_json_parser_valid_and_invalid(self):
        valid_json = '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}'
        data, err = JSONParser.parse_json_string(valid_json)
        self.assertIsNone(err)
        self.assertIn("Resources", data)

        invalid_syntax = '{"Resources": {'
        _, err_inv = JSONParser.parse_json_string(invalid_syntax)
        self.assertIsNotNone(err_inv)

        _, err_empty = JSONParser.parse_json_string("")
        self.assertEqual(err_empty, "File content is empty.")

    def test_format_detection(self):
        cfn_data = {"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}}
        fmt, _ = JSONParser.detect_format(cfn_data)
        self.assertEqual(fmt, JSONParser.FORMAT_CLOUDFORMATION)

        generic_data = {"resources": [{"id": "r1", "type": "storage_bucket"}]}
        fmt_gen, _ = JSONParser.detect_format(generic_data)
        self.assertEqual(fmt_gen, JSONParser.FORMAT_GENERIC)

    def test_validator_missing_resources(self):
        missing_res_data = {"AWSTemplateFormatVersion": "2010-09-09"}
        valid, errors = InputValidator.validate_structure(missing_res_data, JSONParser.FORMAT_CLOUDFORMATION)
        self.assertFalse(valid)

    def test_secure_configuration_zero_findings(self):
        secure_json = json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SecureBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "AccessControl": "Private",
                        "BucketEncryption": {"enabled": True},
                        "LoggingEnabled": True
                    }
                }
            }
        })
        scan_res = self.scanner.scan(secure_json)
        self.assertTrue(scan_res["success"])
        self.assertEqual(scan_res["resources_analyzed"], 1)
        self.assertEqual(len(scan_res["findings"]), 0)

    def test_insecure_configuration_finding_cross_reference(self):
        insecure_json = json.dumps({
            "Resources": {
                "InsecureBucket": {
                    "Type": "AWS::S3::Bucket",
                    "AssetImportance": 90,
                    "Properties": {"AccessControl": "PublicRead"}
                }
            }
        })
        scan_res = self.scanner.scan(insecure_json)
        self.assertTrue(scan_res["success"])
        self.assertGreater(len(scan_res["findings"]), 0)
        
        first_finding = scan_res["findings"][0]
        matching_rule = self.baseline.get_rule_by_id(first_finding["rule_id"])
        self.assertIsNotNone(matching_rule)
        self.assertEqual(first_finding["rule_name"], matching_rule["name"])

    def test_risk_score_calculation(self):
        score = RiskEngine.calculate_risk_score(90, 80)
        self.assertEqual(score, 72.0)
        category = RiskEngine.categorize_risk(score)
        self.assertEqual(category, "High")

    def test_remediation_simulation(self):
        original_data = {"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}}}}
        remediated_data, modified, _ = self.remediator.simulate_remediation(original_data, "CG-AWS-S3-001", "MyBucket", "cloudformation")
        self.assertTrue(modified)
        self.assertEqual(remediated_data["Resources"]["MyBucket"]["Properties"]["AccessControl"], "Private")
        self.assertEqual(original_data["Resources"]["MyBucket"]["Properties"]["AccessControl"], "PublicRead")

    def test_database_persistence(self):
        scan_payload = {
            "format": "cloudformation", "resources_analyzed": 2, "overall_risk_score": 75.0,
            "summary_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"rule_id": "CG-AWS-S3-001", "rule_name": "Public S3", "resource_id": "Bucket1", "resource_type": "AWS::S3::Bucket", "severity": 90, "risk_score": 90.0, "risk_category": "Critical", "observed_value": "PublicRead", "expected_state": "Private", "explanation": "Exposed bucket", "remediation": "Set Private"}]
        }
        scan_id = self.db.save_scan("test_template.json", scan_payload, '{"raw": "json"}')
        self.assertGreater(scan_id, 0)
        history = self.db.get_history(limit=5)
        self.assertEqual(len(history), 1)

if __name__ == "__main__":
    unittest.main()