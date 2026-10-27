import sqlite3
from contextlib import closing
from pathlib import Path
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

import dns_server
from p1_dashboard import decode_json, load_p1_data
from p1_detector import P1Detector


class TestP1Dashboard(unittest.TestCase):
    def test_snapshot_updates_and_history_remains(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            with patch.object(dns_server.sqlite3, "connect", return_value=conn):
                dns_server.initialize_p1_database()
                detector = P1Detector()
                for i in range(3):
                    detector.observe("127.0.0.1", f"x{i}.demo.test", "NXDOMAIN", "LOCAL_TEST", now=i)
                for event in detector.evaluate(now=3):
                    dns_server.save_p1_transition(event)
                dns_server.save_p1_snapshots(detector.snapshots)
                detector.observe("127.0.0.1", "x3.demo.test", "NXDOMAIN", "LOCAL_TEST", now=4)
                for event in detector.evaluate(now=8):
                    dns_server.save_p1_transition(event)
                dns_server.save_p1_snapshots(detector.snapshots)
                current, history = load_p1_data(conn)
                self.assertEqual(len(current), 1)
                self.assertEqual(current.iloc[0]["state"], "ALERT")
                self.assertEqual(history["to_state"].tolist(), ["ALERT", "WATCH"])
                self.assertEqual(decode_json(current.iloc[0]["features_json"], dict)["query_count"], 4)
                for event in detector.evaluate(now=70):
                    dns_server.save_p1_transition(event)
                dns_server.save_p1_snapshots(detector.snapshots)
                current, history = load_p1_data(conn)
                self.assertEqual(current.iloc[0]["state"], "NORMAL")
                self.assertEqual(history["to_state"].tolist(), ["NORMAL", "ALERT", "WATCH"])

    def test_missing_tables(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            current, history = load_p1_data(conn)
            self.assertTrue(current.empty)
            self.assertTrue(history.empty)

    def test_render_and_filter_pairs(self):
        app = AppTest.from_file(str(Path(__file__).parent / 'tests' / 'p1_dashboard_app.py')).run(timeout=15)
        self.assertEqual(len(app.exception), 0)
        self.assertIn("100.0%", app.dataframe[1].value["Value"].tolist())
        self.assertEqual(app.dataframe[-1].value.iloc[0]["domain"], "x.demo.test")
        app.selectbox(key="p1_client").select("127.0.0.2").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.dataframe[0].value["parent_domain"].tolist(), ["shop.test"])
        app.selectbox(key="p1_transition").select(1).run()
        self.assertEqual(len(app.exception), 0)


if __name__ == "__main__":
    unittest.main()
