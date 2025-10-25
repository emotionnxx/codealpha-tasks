#!/usr/bin/env python3
"""
py_sniffer.py
Simple scapy-based sniffer that:
 - captures packets (duration or count)
 - writes a pcap file
 - prints live summary (protocol counts, top src/dst)
 - extracts DNS queries and simple HTTP Host/URI and Authorization headers if present
Usage examples:
  sudo python3 py_sniffer.py -i eth0 -t 60 -f "udp port 53 or icmp or tcp port 80"
  sudo python3 py_sniffer.py -i eth0 -c 200
"""
import argparse
import time
from collections import Counter, defaultdict
from scapy.all import sniff, wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

def parse_args():
    p = argparse.ArgumentParser(description="Simple Python network sniffer (Scapy)")
    p.add_argument("-i", "--iface", required=True, help="Interface to capture on (e.g. eth0)")
    p.add_argument("-t", "--time", type=int, default=0, help="Capture duration in seconds (mutually exclusive with -c)")
    p.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (mutually exclusive with -t)")
    p.add_argument("-f", "--filter", default="", help="BPF filter (tcp, udp, port 80, icmp, \"host 1.2.3.4\", etc.)")
    p.add_argument("-o", "--out", default="task1_sniffer.pcap", help="Output pcap filename")
    return p.parse_args()

# Global accumulators
proto_counter = Counter()
src_counter = Counter()
dst_counter = Counter()
dns_queries = []
http_requests = []
auth_headers = []

def packet_handler(pkt):
    # Timestamp
    proto = "OTHER"
    src = None
    dst = None

    # Ethernet/IP/IPv6
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    else:
        # keep MAC-level if no IP
        if Ether in pkt:
            src = pkt[Ether].src
            dst = pkt[Ether].dst

    # Protocol determination
    if pkt.haslayer(TCP):
        proto = "TCP"
    elif pkt.haslayer(UDP):
        proto = "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    elif pkt.haslayer(DNS):
        proto = "DNS"
    else:
        proto = pkt.summary().split(" ")[0]

    proto_counter[proto] += 1
    if src:
        src_counter[src] += 1
    if dst:
        dst_counter[dst] += 1

    # DNS queries
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # qr==0 => query
        try:
            qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else None
        except Exception:
            qname = str(pkt[DNS].qd.qname) if pkt[DNS].qd else None
        dns_queries.append((time.strftime("%Y-%m-%d %H:%M:%S"), src, qname))

    # Try to pick HTTP info from Raw payload if present and TCP port 80
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        # decode safely
        try:
            text = payload.decode('utf-8', errors='ignore')
        except:
            text = ""
        # simple HTTP request detection
        if text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
            # find Host: header
            host = None
            uri = None
            head_lines = text.split("\r\n")
            if len(head_lines) > 0:
                method_uri = head_lines[0].split(" ")
                if len(method_uri) > 1:
                    uri = method_uri[1]
            for line in head_lines:
                if line.lower().startswith("host:"):
                    host = line.split(":",1)[1].strip()
                if line.lower().startswith("authorization:"):
                    auth_headers.append((time.strftime("%Y-%m-%d %H:%M:%S"), src, line.strip()))
            http_requests.append((time.strftime("%Y-%m-%d %H:%M:%S"), src, host, uri))

def print_summary():
    print("\n=== Capture Summary ===")
    print("Protocol counts:")
    for proto, cnt in proto_counter.most_common():
        print(f"  {proto:6} : {cnt}")
    print("\nTop 10 Sources:")
    for ip, cnt in src_counter.most_common(10):
        print(f"  {ip:20} : {cnt}")
    print("\nTop 10 Destinations:")
    for ip, cnt in dst_counter.most_common(10):
        print(f"  {ip:20} : {cnt}")
    if dns_queries:
        print("\nRecent DNS queries (time, src, qname):")
        for t, s, q in dns_queries[-10:]:
            print(f"  {t} {s} -> {q}")
    if http_requests:
        print("\nHTTP requests (time, src, host, uri) recent:")
        for t, s, h, u in http_requests[-10:]:
            print(f"  {t} {s} -> Host: {h} URI: {u}")
    if auth_headers:
        print("\nAuthorization headers found (redact before sharing):")
        for t, s, h in auth_headers[-10:]:
            print(f"  {t} {s} : {h}")

def main():
    args = parse_args()
    bpf = args.filter if args.filter else None
    print(f"[+] Starting capture on interface {args.iface} ... filter: {bpf}")
    # sniff options
    kwargs = {"iface": args.iface, "prn": packet_handler, "store": True}
    if args.time and args.time > 0:
        kwargs["timeout"] = args.time
    if args.count and args.count > 0:
        kwargs["count"] = args.count
    if bpf:
        kwargs["filter"] = bpf

    pkts = sniff(**kwargs)  # blocking until done
    print(f"[+] Capture complete: {len(pkts)} packets captured.")
    # write pcap
    out = args.out
    wrpcap(out, pkts)
    print(f"[+] Saved pcap to: {out}")
    # print summary
    print_summary()

if __name__ == "__main__":
    main()