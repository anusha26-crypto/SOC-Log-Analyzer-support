import tempfile
import unittest
from pathlib import Path
from main import analyze_logs, format_report

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.csv_path = Path(self.tmp.name) / "logs.csv"
        self.csv_path.write_text(
            "timestamp,username,src_ip,event\n"
            "2026-10-28T09:00:00,sam,198.51.100.23,failure\n"
            "2026-10-28T09:01:00,sam,198.51.100.23,failure\n"
            "2026-10-28T09:02:00,sam,198.51.100.23,failure\n"
            "2026-10-28T09:03:00,alex,192.0.2.10,success\n",
            encoding="utf-8"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts_and_alert(self):
        result = analyze_logs(self.csv_path, threshold=3)
        self.assertEqual(result["total"], 4)
        self.assertEqual(result["successes"], 1)
        self.assertEqual(result["failures"], 3)
        self.assertEqual(len(result["alerts"]), 2)

    def test_threshold_above_failures_no_alert(self):
        result = analyze_logs(self.csv_path, threshold=4)
        self.assertEqual(len(result["alerts"]), 0)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_logs(self.csv_path, threshold=0)

    def test_invalid_event(self):
        bad = Path(self.tmp.name) / "bad.csv"
        bad.write_text("timestamp,username,src_ip,event\nx,u,192.0.2.1,unknown\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            analyze_logs(bad)

if __name__ == "__main__":
    unittest.main()
