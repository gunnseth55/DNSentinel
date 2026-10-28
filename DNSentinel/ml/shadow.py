"""Bounded, fail-open M1 worker. PyTorch is imported only in the worker thread."""
import json
import queue
import sqlite3
import threading
from datetime import datetime, timezone
from uuid import uuid4


def initialize_m1_database(db_path):
    with sqlite3.connect(db_path, timeout=1) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS m1_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, client_ip TEXT NOT NULL,
            domains_json TEXT NOT NULL, parent_domains_json TEXT NOT NULL,
            reconstruction_error REAL NOT NULL, threshold REAL NOT NULL,
            anomaly INTEGER NOT NULL, model_version TEXT NOT NULL,
            sequence_size INTEGER NOT NULL, configured_sequence_size INTEGER NOT NULL,
            distribution_warnings_json TEXT NOT NULL, session_id TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS m1_runtime (
            id INTEGER PRIMARY KEY CHECK (id=1), timestamp TEXT NOT NULL,
            status TEXT NOT NULL, details_json TEXT NOT NULL
        )""")


class M1Shadow:
    def __init__(self, db_path, checkpoint, enabled=True, queue_size=256):
        self.db_path, self.checkpoint = db_path, checkpoint
        self.session = uuid4().hex
        self.queue = queue.Queue(maxsize=queue_size)
        self.stopping = threading.Event()
        self.dropped = self.errors = self.predictions = self.observations = 0
        self.accepting = enabled
        self.thread = None
        self.details = {"session_id": self.session, "checkpoint": str(checkpoint),
                        "shadow_only": True}
        try:
            initialize_m1_database(db_path)
            self._status("LOADING" if enabled else "DISABLED")
        except Exception as error:
            self.accepting = False
            print(f"M1 disabled: database initialization failed: {error}", flush=True)
            return
        if enabled:
            self.thread = threading.Thread(target=self._run, name="M1-shadow", daemon=True)
            self.thread.start()

    def _status(self, state, **details):
        self.details.update(details)
        self.details.update(observations=self.observations, predictions=self.predictions,
                            errors=self.errors, dropped_observations=self.dropped,
                            queued=self.queue.qsize())
        try:
            with sqlite3.connect(self.db_path, timeout=0.25) as conn:
                conn.execute("""INSERT INTO m1_runtime VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET timestamp=excluded.timestamp,
                        status=excluded.status, details_json=excluded.details_json""",
                             (datetime.now(timezone.utc).isoformat(), state,
                              json.dumps(self.details)))
        except sqlite3.Error as error:
            print(f"M1 status persistence error: {error}", flush=True)

    def submit(self, observation):
        if not self.accepting:
            return
        try:
            self.queue.put_nowait(dict(observation, session_id=f"{self.session}:{self.dropped}"))
        except queue.Full:
            self.dropped += 1
            # The counter changes the observation session after a drop, preventing
            # a sequence from silently bridging missing queries.

    def _save(self, result):
        with sqlite3.connect(self.db_path, timeout=0.25) as conn:
            conn.execute("""INSERT INTO m1_predictions
                (timestamp, client_ip, domains_json, parent_domains_json,
                 reconstruction_error, threshold, anomaly, model_version,
                 sequence_size, configured_sequence_size, distribution_warnings_json, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                    result["prediction_timestamp"], result["client_ip"],
                    json.dumps(result["domains"]), json.dumps(result["parent_domains"]),
                    result["model_output"], result["decision_threshold"],
                    int(result["exceeds_threshold"]), result["model_version"],
                    result["sequence_length"], result["configured_sequence_length"],
                    json.dumps(result["distribution_warnings"]), self.session))

    def _run(self):
        try:
            from ml.inference import M1Predictor
            predictor = M1Predictor(self.checkpoint, non_overlapping=True)
            predictor.torch.set_num_threads(2)
            if predictor.model.mode != "benign_autoencoder":
                raise ValueError("Live M1 requires the existing benign autoencoder")
            self.details.update(model_version=predictor.version, threshold=predictor.threshold,
                                sequence_length=predictor.schema["sequence_length"],
                                group_by=predictor.schema["group_by"],
                                include_responses=predictor.schema["include_responses"],
                                feature_names=predictor.schema["feature_names"])
            self._status("RUNNING", last_error=None)
            print(f"M1 shadow ready: {predictor.version} | "
                  f"{predictor.schema['sequence_length']} queries/{predictor.schema['group_by']} | "
                  f"threshold={predictor.threshold:.6f}", flush=True)
        except (Exception, SystemExit) as error:
            self.accepting = False
            self._status("ERROR", last_error=str(error))
            print(f"M1 unavailable; DNS continues: {error}", flush=True)
            return
        while not self.stopping.is_set() or not self.queue.empty():
            try:
                observation = self.queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                result = predictor.observe(observation)
                self.observations += 1
                if result is not None:
                    self._save(result)
                    self.predictions += 1
                    print(f"[M1 SHADOW] {result['client_ip']} | error={result['model_output']:.6f} "
                          f"threshold={result['decision_threshold']:.6f} | "
                          f"{'ANOMALY' if result['exceeds_threshold'] else 'NORMAL'}", flush=True)
                progress = [{"client_ip": key[2], "parent_domain": key[3], "pending": len(value)}
                            for key, value in list(predictor.buffers.items())[-32:]]
                self._status("RUNNING", progress=progress, last_error=None)
            except Exception as error:
                self.errors += 1
                predictor.buffers.clear()
                predictor.last_activity.clear()
                self._status("DEGRADED", last_error=str(error))
                print(f"M1 observation error; DNS continues: {error}", flush=True)
            finally:
                self.queue.task_done()
        self._status("STOPPED")

    def close(self):
        self.accepting = False
        self.stopping.set()
        if self.thread:
            self.thread.join(timeout=3)
