import unittest
from detector import detect

class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"timestamp": f"2026-10-27T09:0{i}:00+05:30", "username": "alice", "src_ip": "10.0.0.5", "event_id": "4625", "hostname": "WS-1"}
            for i in range(5)
        ] + [
            {"timestamp": "2026-10-27T09:06:00+05:30", "username": "alice", "src_ip": "10.0.0.5", "event_id": "4624", "hostname": "WS-1"}
        ]
    def test_bruteforce_alert(self):
        alerts = detect(self.events, threshold=5, window_minutes=10)
        self.assertIn("DET-001", [a.rule_id for a in alerts])
    def test_success_after_failures(self):
        alerts = detect(self.events, threshold=5, window_minutes=10)
        self.assertIn("DET-003", [a.rule_id for a in alerts])
    def test_no_alert_below_threshold(self):
        alerts = detect(self.events[:3], threshold=5, window_minutes=10)
        self.assertNotIn("DET-001", [a.rule_id for a in alerts])

if __name__ == "__main__":
    unittest.main()
