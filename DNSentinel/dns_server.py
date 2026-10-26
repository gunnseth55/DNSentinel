import socket
import sqlite3
from datetime import datetime
from pathlib import Path
from dnslib import DNSRecord, DNSError, QTYPE, RCODE, RR, A
from behavior import DNSBehaviourDetector
from security import analyze_dns_query

HOST="127.0.0.1"
PORT=5300

UPSTREAM_DNS = "1.1.1.1"
UPSTREAM_PORT = 53
DB_PATH = Path(__file__).parent / "dns_events.db"


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
#dns server

def start_dns_server():     
    initialize_database()
    server=socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM  
    )
    server.bind((HOST,PORT))
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
            data,client_address=server.recvfrom(4096)
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

                log_request(
                    client_address[0],
                    domain,
                    query_type,
                    status,
                    response_code
                )

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

if __name__=="__main__":
    start_dns_server()
