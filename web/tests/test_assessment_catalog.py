import sqlite3
import tempfile
import unittest
from pathlib import Path

from web.app import db
from web.app.assessment_catalog import enrich_assessment, lookup


class AssessmentCatalogTests(unittest.TestCase):
    def test_biometric_is_platform_specific(self):
        android = lookup("ASSESS-BIOMETRIC", "ANDROID")
        ios = lookup("ASSESS-BIOMETRIC", "IOS")
        self.assertIn("BiometricPrompt", android["summary"])
        self.assertIn("LocalAuthentication", ios["summary"])
        self.assertNotEqual(android["summary"], ios["summary"])
        self.assertGreaterEqual(len(android["static_checks"]), 2)
        self.assertGreaterEqual(len(android["dynamic_checks"]), 2)

    def test_unknown_control_still_has_howto(self):
        guide = lookup("ASSESS-NOT-A-REAL-CONTROL", "ANDROID", "Custom control")
        self.assertIn("Custom control", guide["summary"])
        self.assertTrue(guide["static_checks"])
        self.assertTrue(guide["dynamic_checks"])

    def test_any_platform_vendor_guide(self):
        guide = lookup("ASSESS-OBFUSCATOR-VENDOR", "IOS")
        self.assertIn("vendor", guide["summary"].lower())


class AssessmentApiEnrichmentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        handle.close()
        self.db_path = handle.name
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE Assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ControlId TEXT,
                    Title TEXT,
                    Category TEXT,
                    Status TEXT,
                    Confidence TEXT,
                    Evidence TEXT,
                    Detail TEXT,
                    Platform TEXT,
                    ExecutableName TEXT,
                    CreatedAt INTEGER
                )"""
            )
            conn.execute(
                """INSERT INTO Assessments
                   (ControlId, Title, Category, Status, Confidence,
                    Evidence, Detail, Platform, ExecutableName, CreatedAt)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "ASSESS-BIOMETRIC",
                    "BiometricPrompt / fingerprint auth",
                    "AUTH",
                    "ABSENT",
                    "MEDIUM",
                    "No matching signals in strings/decompilation/resources",
                    "",
                    "ANDROID",
                    "Target",
                    1,
                ),
            )

    def tearDown(self):
        Path(self.db_path).unlink(missing_ok=True)

    async def test_old_sqlite_row_gets_catalog_fields(self):
        rows = await db.get_assessments(self.db_path, "Target")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["control_id"], "ASSESS-BIOMETRIC")
        self.assertEqual(
            row["evidence"],
            "No matching signals in strings/decompilation/resources",
        )
        self.assertIn("BiometricPrompt", row["summary"])
        self.assertTrue(row["static_checks"])
        self.assertTrue(row["dynamic_checks"])
        self.assertTrue(all("frida -U" not in s.lower() for s in row["dynamic_checks"]))

    def test_enrich_does_not_drop_reason(self):
        row = enrich_assessment(
            {
                "control_id": "ASSESS-UNKNOWN-OLD",
                "title": "Legacy control",
                "evidence": "scanner reason",
                "platform": "ANDROID",
            }
        )
        self.assertEqual(row["evidence"], "scanner reason")
        self.assertIn("Legacy control", row["summary"])
        self.assertTrue(row["static_checks"])


if __name__ == "__main__":
    unittest.main()
