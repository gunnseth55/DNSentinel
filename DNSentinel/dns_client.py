
import sys
from dnslib import DNSRecord, DNSQuestion, RCODE

DNS_SERVER = "127.0.0.1"
DNS_PORT = 5300


def query_dns(domain, record_type="A"):
    print(f"\nQuerying: {domain}")
    print(f"DNS Server: {DNS_SERVER}:{DNS_PORT}")

    try:
        type_text = str(record_type).upper()
        numeric = type_text[4:] if type_text.startswith("TYPE") else type_text
        if numeric.isdecimal():
            code = int(numeric)
            if not 0 <= code <= 65535:
                raise ValueError("DNS type must be between 0 and 65535")
            request = DNSRecord(q=DNSQuestion(domain, code))
        else:
            request = DNSRecord.question(domain, type_text)
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
