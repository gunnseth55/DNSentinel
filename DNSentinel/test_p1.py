import unittest
from p1_detector import P1Detector


class TestP1(unittest.TestCase):
    def test_current_snapshot_without_state_transition(self):
        d = P1Detector()
        d.observe("127.0.0.1", "a.demo.test", "NOERROR", "LOCAL", now=0)
        self.assertEqual(d.evaluate(now=0), [])
        self.assertEqual(d.snapshots[0]["to_state"], "NORMAL")
        self.assertEqual(d.snapshots[0]["features"]["query_count"], 1)
        d.evaluate(now=1)
        self.assertEqual(d.snapshots, [])
        d.observe("127.0.0.1", "a.demo.test", "NOERROR", "LOCAL", now=2)
        self.assertEqual(d.evaluate(now=5), [])
        self.assertEqual(d.snapshots[0]["features"]["query_count"], 2)
        d.evaluate(now=70)
        self.assertEqual(d.snapshots[0]["features"]["query_count"], 0)
        self.assertEqual(d.snapshots[0]["to_state"], "NORMAL")

    def test_watch_then_alert_then_expiry(self):
        d = P1Detector()
        for i in range(3):
            self.assertTrue(d.observe("127.0.0.1", f"x{i}.demo.test", "NXDOMAIN", "LOCAL_TEST", now=float(i)))
        events = d.evaluate(now=3)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["to_state"], "WATCH")
        self.assertFalse(events[0]["evidence"]["response"])

        d.observe("127.0.0.1", "x3.demo.test", "NXDOMAIN", "LOCAL_TEST", now=4)
        events = d.evaluate(now=8)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["from_state"], events[0]["to_state"]), ("WATCH", "ALERT"))
        self.assertTrue(events[0]["evidence"]["response"])

        events = d.evaluate(now=70)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["from_state"], events[0]["to_state"]), ("ALERT", "NORMAL"))

    def test_repeated_name_does_not_trigger(self):
        d = P1Detector()
        for i in range(5):
            d.observe("127.0.0.1", "a.demo.test", "NXDOMAIN", "LOCAL_TEST", now=i)
        self.assertEqual(d.evaluate(now=5), [])

    def test_blocked_response_is_not_nxdomain_evidence(self):
        d = P1Detector()
        for i in range(5):
            self.assertFalse(d.observe("127.0.0.1", f"x{i}.demo.test", "REFUSED", "BLOCKED", now=i))
        self.assertEqual(d.evaluate(now=5), [])

    def test_separate_domain_groups(self):
        d = P1Detector()
        for i in range(3):
            d.observe("127.0.0.1", f"x{i}.shop.test", "NXDOMAIN", "LOCAL_TEST", now=i)
            d.observe("127.0.0.1", f"x{i}.demo.test", "NXDOMAIN", "LOCAL_TEST", now=i)
        groups = {e["parent_domain"] for e in d.evaluate(now=5)}
        self.assertEqual(groups, {"shop.test", "demo.test"})


if __name__ == "__main__":
    unittest.main()
