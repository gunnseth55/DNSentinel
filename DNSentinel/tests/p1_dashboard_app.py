import json
import pandas as pd
from p1_dashboard import render_p1
evidence = json.dumps({"naming": True, "timing": False, "response": True})
features = json.dumps({"query_count": 4, "unique_subdomains": 4, "nxdomain_ratio": 1.0})
samples = json.dumps([{"domain": "x.demo.test", "response": "NXDOMAIN", "source": "LOCAL_TEST"}])
base = dict(timestamp="2026-10-27T00:00:00+00:00", evidence_json=evidence, features_json=features, samples_json=samples)
current = pd.DataFrame([
    dict(base, client_ip="127.0.0.1", parent_domain="demo.test", state="ALERT"),
    dict(base, client_ip="127.0.0.2", parent_domain="shop.test", state="WATCH"),
])
history = pd.DataFrame([
    dict(base, id=2, client_ip="127.0.0.1", parent_domain="demo.test", from_state="WATCH", to_state="ALERT"),
    dict(base, id=1, client_ip="127.0.0.2", parent_domain="shop.test", from_state="NORMAL", to_state="WATCH"),
])
render_p1(current, history)
