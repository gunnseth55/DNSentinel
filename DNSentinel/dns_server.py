import socket
import sqlite3
import os
import time
from datetime import datetime
from pathlib import Path
from dnslib import DNSRecord, DNSError, QTYPE, RCODE, RR, A
from behavior import DNSBehaviourDetector
from security import analyze_dns_query
import json
from datetime import timezone
from p1_detector import P1Detector
from b1_detector import B1Detector

# Use configuration="core" for R1-R5; Expanded also enables R6, R7 and R8.
# Pass B1Thresholds(...) and cooldown_seconds=... to customize defaults.
b1_detector = B1Detector(configuration="expanded")

p1_detector = P1Detector(
    window_seconds=60,
    interval_seconds=5
)
HOST="127.0.0.1"
PORT=5300

UPSTREAM_DNS = "1.1.1.1"
UPSTREAM_PORT = 53
DB_PATH = Path(os.environ.get("DNSENTINEL_DB_PATH", Path(__file__).parent / "dns_events.db"))


BLOCKED_DOMAINS = {
    "blocked.test",
    "malware.test",
    "phishing.test",
}

behaviour_detector = DNSBehaviourDetector()

#database

def initialize_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
              CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                domain TEXT,
                query_type TEXT,
                status TEXT,
                response_code TEXT
            )

        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                domain TEXT,
                detector TEXT,
                risk TEXT,
                score INTEGER,
                reasons TEXT
            )
        """)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(dns_alerts)")}
        for column, kind in {
            "triggered_rules": "TEXT", "features_json": "TEXT",
            "rule_details_json": "TEXT", "incident_id": "TEXT",
            "configuration": "TEXT", "last_seen": "TEXT", "occurrences": "INTEGER",
        }.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE dns_alerts ADD COLUMN {column} {kind}")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS dns_alerts_incident ON dns_alerts(incident_id)")
def log_request(client_ip,domain, query_type,status, response_code):
    timestamp=datetime.now().isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO dns_logs
            (timestamp, client_ip, domain,
             query_type, status, response_code)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            client_ip,
            domain,
            query_type,
            status,
            response_code
        ))
    print(
        f"[{timestamp}] "
        f"{client_ip} | {domain} | {query_type} | "
        f"{status} | {response_code}",
        flush=True
    )

#domain filtering

def is_blocked(domain):
    for blocked in BLOCKED_DOMAINS:
        if domain==blocked or domain.endswith("."+blocked):
            return True
    return False

#dns processing
def process_dns_request(request):
    domain=str(request.q.qname).rstrip(".").lower()
    query_type=QTYPE[request.q.qtype]

    if is_blocked(domain):
        reply=request.reply(aa=0)
        reply.header.rcode=RCODE.REFUSED
        return reply,domain,query_type,"BLOCKED"

    if domain=="demo.test":
        reply=request.reply(aa=1)
        if request.q.qtype == QTYPE.A:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=60,
                    rdata=A("192.0.2.10")
                )
            )

        return reply, domain, query_type, "LOCAL"
    if domain=="test" or domain.endswith(".test"):
        reply=request.reply(aa=1)
        reply.header.rcode=RCODE.NXDOMAIN
        return reply,domain,query_type,"LOCAL_TEST"

    try:
        response_data=request.send(
            UPSTREAM_DNS,
            UPSTREAM_PORT,
            timeout=3
        )
        reply=DNSRecord.parse(response_data)
        #checking of the upstream request matches our request
        if( reply.header.qr != 1
            or reply.header.id != request.header.id
            or len(reply.questions) != 1
            or reply.q.qname != request.q.qname
            or reply.q.qtype != request.q.qtype
            or reply.q.qclass != request.q.qclass):
            raise DNSError("unexpected upstream DNS response")
        return reply, domain, query_type, "FORWARDED"
    except(OSError, DNSError) as error:
        print(f"Upstream DNS error: {error}")

        reply = request.reply(aa=0)
        reply.header.rcode = RCODE.SERVFAIL

        return reply, domain, query_type, "ERROR"

#security
def log_security_alert(client_ip, result, detector="BASELINE"):

    if result["risk"] == "LOW":
        return

    timestamp = datetime.now().isoformat(
        timespec="seconds"
    )

    reasons = "; ".join(result["reasons"])

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO dns_alerts
            (timestamp, client_ip, domain,
             detector, risk, score, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            client_ip,
            result["domain"],
            detector,
            result["risk"],
            result["score"],
            reasons
        ))

def log_b1_alert(result):
    """Merge one continuing B1 incident into the existing alert table."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO dns_alerts
                (timestamp, client_ip, domain, detector, risk, score, reasons,
                 triggered_rules, features_json, rule_details_json, incident_id,
                 configuration, last_seen, occurrences)
            VALUES (?, ?, ?, 'B1', ?, NULL, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(incident_id) DO UPDATE SET
                risk=excluded.risk, reasons=excluded.reasons,
                triggered_rules=excluded.triggered_rules,
                features_json=excluded.features_json,
                rule_details_json=excluded.rule_details_json,
                last_seen=excluded.last_seen,
                occurrences=dns_alerts.occurrences + 1
        """, (
            result["timestamp"], result["client_ip"], result["domain"],
            result["severity"], "; ".join(result["reasons"]),
            json.dumps(result["triggered_rules"]), json.dumps(result["features"]),
            json.dumps(result["rule_details"]), result["incident_id"],
            result["configuration"], result["timestamp"],
        ))
    if result["new_incident"] or result["new_rules"]:
        print(f"\n[B1 ALERT] {result['client_ip']} | {result['domain']} | "
              f"{result['severity']} | {', '.join(result['triggered_rules'])}", flush=True)
        for reason in result["reasons"]:
            print("Reason:", reason, flush=True)


def initialize_p1_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS p1_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                parent_domain TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                features_json TEXT NOT NULL,
                samples_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS p1_current (
                client_ip TEXT NOT NULL,
                parent_domain TEXT NOT NULL,
                state TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                features_json TEXT NOT NULL,
                samples_json TEXT NOT NULL,
                PRIMARY KEY (client_ip, parent_domain)
            )
        """)


def save_p1_snapshots(snapshots):
    if not snapshots:
        return
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany("""
            INSERT INTO p1_current
                (client_ip, parent_domain, state, timestamp,
                 evidence_json, features_json, samples_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(client_ip, parent_domain) DO UPDATE SET
                state=excluded.state, timestamp=excluded.timestamp,
                evidence_json=excluded.evidence_json,
                features_json=excluded.features_json,
                samples_json=excluded.samples_json
        """, [(
            event["client_ip"], event["parent_domain"], event["to_state"],
            timestamp, json.dumps(event["evidence"]),
            json.dumps(event["features"]), json.dumps(event["samples"])
        ) for event in snapshots])

#SQlite table for transactions
def save_p1_transition(event):
    timestamp = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO p1_transitions (
                timestamp, client_ip, parent_domain,
                from_state, to_state,
                evidence_json, features_json, samples_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            event["client_ip"],
            event["parent_domain"],
            event["from_state"],
            event["to_state"],
            json.dumps(event["evidence"]),
            json.dumps(event["features"]),
            json.dumps(event["samples"])
        ))

    print(
        f"\n[P1] {event['client_ip']} | "
        f"{event['parent_domain']} | "
        f"{event['from_state']} -> {event['to_state']}"
    )
    print("Evidence:", event["evidence"])
    print("Features:", event["features"])


#dns server

def start_dns_server():     
    initialize_database()
    initialize_p1_database()
    server=socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM  
    )
    server.bind((HOST,PORT))
    # Detector state lives in memory, so a new server starts a new current view.
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM p1_current")
    server.settimeout(1.0)
    m1 = None
    try:
        from ml.shadow import M1Shadow
        checkpoint = Path(os.environ.get(
            "DNSENTINEL_M1_CHECKPOINT", Path(__file__).parent / "models/gru/m1_benign_ae/best.pt"))
        m1 = M1Shadow(DB_PATH, checkpoint,
                      enabled=os.environ.get("DNSENTINEL_M1", "1").lower() not in ("0", "false", "off"))
    except Exception as error:
        print(f"M1 unavailable; DNS continues: {error}", flush=True)
    print("="*50)
    print("        DNSENTINEL - DNS SECURITY SERVER")
    print("=" * 50)

    print(f"Listening on : {HOST}:{PORT}")
    print(f"Upstream DNS : {UPSTREAM_DNS}")
    print(f"Blocked      : {len(BLOCKED_DOMAINS)} domains")
    print(f"Database     : {DB_PATH}")
    print("=" * 50)
    print("Waiting for DNS requests...\n", flush=True)
    try:
        while True:
            for transition in p1_detector.evaluate():
                save_p1_transition(transition)
            save_p1_snapshots(p1_detector.snapshots)

            try:
                data, client_address = server.recvfrom(4096)
                query_arrival = time.monotonic()
            except socket.timeout:
                continue
            
            print(
                f"PACKET RECEIVED: {len(data)} bytes from {client_address}",
                flush=True
            )
            try:
                request=DNSRecord.parse(data)
                if request.header.qr != 0:
                    continue

                if (
                    request.header.opcode != 0
                    or len(request.questions) != 1
                ):
                    reply = request.reply(aa=0)
                    reply.header.rcode = RCODE.FORMERR
                    server.sendto(reply.pack(), client_address)
                    continue

                reply, domain, query_type, status = (
                    process_dns_request(request)
                )

                server.sendto(
                    reply.pack(),
                    client_address
                )

                response_code = RCODE[reply.header.rcode]

                # Completed observation; arrival time, not response completion, defines gaps.
                # Queueing never waits for inference and cannot change the DNS reply.
                if m1 is not None:
                    try:
                        m1.submit({
                            "client_ip": client_address[0], "qname": domain,
                            "qtype_numeric": request.q.qtype,
                            "timestamp_monotonic_s": query_arrival,
                            "response_matched": status != "ERROR",
                            "response_code_numeric": reply.header.rcode,
                        })
                    except Exception as error:
                        print(f"M1 queue error; DNS continues: {error}", flush=True)

                log_request(
                    client_address[0],
                    domain,
                    query_type,
                    status,
                    response_code
                )
                p1_detector.observe(
                    client_ip=client_address[0],
                    domain=domain,
                    response_code=response_code,
                    status=status
                )
                # Independent observer: never modifies the DNS reply or P1 state.
                try:
                    b1_alert = b1_detector.observe(
                        client_address[0], domain, request.q.qtype,
                        response_code, status,
                    )
                    if b1_alert:
                        log_b1_alert(b1_alert)
                except Exception as error:
                    print(f"B1 observation error: {error}", flush=True)
                # Analyze the DNS query
                analysis = analyze_dns_query(domain)
                
                if analysis["risk"] != "LOW":
                
                    log_security_alert(
                        client_address[0],
                        analysis
                    )
                
                    print("\n[SECURITY ALERT]")
                    print("Domain:", domain)
                    print("Risk:", analysis["risk"])
                    print("Score:", analysis["score"])
                
                    for reason in analysis["reasons"]:
                        print("Reason:", reason)
                
                #behavioral detection

                behaviour_result = behaviour_detector.analyze(
                    client_address[0],
                    domain,
                    response_code
                )

                if behaviour_result:
                
                    log_security_alert(
                        client_address[0],
                        behaviour_result,
                        detector="BEHAVIOUR"
                    )

                    print("\n[BEHAVIOURAL SECURITY ALERT]")
                    print("Domain group:", behaviour_result["domain"])
                    print("Risk:", behaviour_result["risk"])
                    print("Score:", behaviour_result["score"])

                    for reason in behaviour_result["reasons"]:
                        print("Reason:", reason)

                    print("-" * 40)
            except DNSError as error:
                print(f"Invalid DNS packet: {error}")
            except Exception as error:
                print(f"Request processing error: {error}")
    except KeyboardInterrupt:
        print("\nStopping DNSentinel...")
    finally:
        server.close()
        if m1 is not None:
            m1.close()

if __name__=="__main__":
    start_dns_server()
