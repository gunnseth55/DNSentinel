
import sys
from dnslib import DNSRecord, RCODE

DNS_SERVER = "127.0.0.1"
DNS_PORT = 5300


def query_dns(domain, record_type="A"):
    request = DNSRecord.question(domain, record_type)

    print(f"\nQuerying: {domain}")
    print(f"DNS Server: {DNS_SERVER}:{DNS_PORT}")

    try:
        response_data = request.send(
            DNS_SERVER,
            DNS_PORT,
            timeout=5
        )

        response = DNSRecord.parse(response_data)

        print("Response:", RCODE[response.header.rcode])

        for answer in response.rr:
            print(answer)

    except Exception as error:
        print("DNS query failed:", error)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_client.py DOMAIN [TYPE]")
        sys.exit(1)

    domain = sys.argv[1]
    record_type = sys.argv[2].upper() if len(sys.argv) > 2 else "A"

    query_dns(domain, record_type)
