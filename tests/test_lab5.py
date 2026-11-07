from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from viruswall.network import ConnectionInfo, NetworkAnalyzer, NetworkRules, parse_packet


def test_connection_rules():
    rules = NetworkRules(max_connections=2, max_distinct_ips=2, max_repeats=2,
                         suspicious_ips=("203.0.113.10",))
    analyzer = NetworkAnalyzer(rules, clock=lambda: 100.0)
    first = ConnectionInfo("tcp", "127.0.0.1", 5000, "203.0.113.10", 443, "ESTABLISHED", 1, "unknown", "now")
    second = ConnectionInfo("tcp", "127.0.0.1", 5001, "198.51.100.20", 443, "ESTABLISHED", 1, "unknown", "now")
    assert any(f.rule == "suspicious_ip" for f in analyzer.analyze_connection(first))
    assert {f.rule for f in analyzer.analyze_connection(second)} >= {"connection_burst", "many_destinations"}


def test_packet_dns_and_rules():
    packet = IP(src="127.0.0.1", dst="8.8.8.8") / UDP(sport=1111, dport=53) / DNS(rd=1, qd=DNSQR(qname="bad.example"))
    info = parse_packet(packet)
    assert info.dns_query == "bad.example" and info.protocol == "udp"
    analyzer = NetworkAnalyzer(NetworkRules(max_dns_queries=1, suspicious_dns_suffixes=("example",)))
    assert {f.rule for f in analyzer.analyze_packet(info)} == {"suspicious_dns", "dns_burst"}
    analyzer.analyze_packet(info)
    assert analyzer.flows()[0]["packets"] == 2
    assert analyzer.flows()[0]["bytes"] == 2 * info.length


def test_non_ip_packet_ignored():
    from scapy.layers.l2 import Ether
    assert parse_packet(Ether()) is None
