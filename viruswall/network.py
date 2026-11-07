"""Пассивный мониторинг соединений и пакетов локальной станции."""

from collections import deque
from dataclasses import asdict, dataclass
import ipaddress
import socket
import time
from typing import Iterable

from .models import Finding, now_utc


@dataclass(frozen=True)
class ConnectionInfo:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str | None
    remote_port: int | None
    state: str
    pid: int | None
    direction: str
    observed_at: str

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class PacketInfo:
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    dns_query: str | None
    observed_at: str
    length: int = 0

    def to_dict(self):
        return asdict(self)


def list_interfaces() -> dict[str, list[str]]:
    """Вернуть интерфейсы и их IPv4/IPv6 адреса."""
    import psutil
    result = {}
    for name, addresses in psutil.net_if_addrs().items():
        result[name] = [item.address for item in addresses if item.family in (socket.AF_INET, socket.AF_INET6)]
    return result


def list_connections() -> list[ConnectionInfo]:
    """Список доступных ОС соединений; направление не всегда определимо."""
    import psutil
    found = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        raise PermissionError("ОС запретила просмотр сетевых соединений") from exc
    listeners = {(item.laddr.ip, item.laddr.port) for item in connections
                 if item.type == socket.SOCK_STREAM and item.status == "LISTEN" and item.laddr}
    for item in connections:
        local = item.laddr
        if not local:
            continue
        remote = item.raddr
        proto = "tcp" if item.type == socket.SOCK_STREAM else "udp"
        # Направление established TCP выводится по локальному слушающему порту.
        direction = "listening" if item.status == "LISTEN" else "unknown"
        if proto == "tcp" and remote and item.status == "ESTABLISHED":
            direction = "inbound_inferred" if (local.ip, local.port) in listeners or ("0.0.0.0", local.port) in listeners or ("::", local.port) in listeners else "outbound_inferred"
        found.append(ConnectionInfo(proto, local.ip, local.port, remote.ip if remote else None,
                                    remote.port if remote else None, item.status, item.pid,
                                    direction, now_utc()))
    return found


def parse_packet(packet) -> PacketInfo | None:
    """Извлечь только метаданные IP/TCP/UDP/DNS, не сохраняя полезную нагрузку."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip is None:
        return None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    protocol = "tcp" if packet.haslayer(TCP) else "udp" if packet.haslayer(UDP) else "ip"
    dns_query = None
    dns = packet.getlayer(DNS)
    if dns and dns.qr == 0 and packet.haslayer(DNSQR):
        raw = packet.getlayer(DNSQR).qname
        dns_query = raw.decode("ascii", errors="replace").rstrip(".")[:255]
    return PacketInfo(str(ip.src), str(ip.dst), protocol,
                      int(transport.sport) if transport else None,
                      int(transport.dport) if transport else None,
                      dns_query, now_utc(), len(packet))


def capture_packets(interface: str, count: int = 20, timeout: float = 5.0) -> list[PacketInfo]:
    """Захватить ограниченное число пакетов выбранного интерфейса без promiscuous режима."""
    if interface not in list_interfaces():
        raise ValueError("Неизвестный интерфейс")
    if not 1 <= count <= 1000 or not 0 < timeout <= 60:
        raise ValueError("Недопустимые ограничения захвата")
    from scapy.sendrecv import sniff
    from scapy.error import Scapy_Exception
    try:
        packets = sniff(iface=interface, count=count, timeout=timeout, store=True, promisc=False,
                        filter="ip or ip6")
    except (OSError, PermissionError, Scapy_Exception) as exc:
        raise PermissionError("Захват пакетов недоступен с текущими правами или без драйвера") from exc
    return [info for packet in packets if (info := parse_packet(packet)) is not None]


@dataclass
class NetworkRules:
    window_seconds: int = 60
    max_connections: int = 30
    max_distinct_ips: int = 20
    max_repeats: int = 10
    max_dns_queries: int = 30
    suspicious_ips: tuple[str, ...] = ()
    suspicious_dns_suffixes: tuple[str, ...] = ()

    def __post_init__(self):
        for address in self.suspicious_ips:
            ipaddress.ip_address(address)
        if min(self.window_seconds, self.max_connections, self.max_distinct_ips,
               self.max_repeats, self.max_dns_queries) <= 0:
            raise ValueError("Пороги правил должны быть положительными")


class NetworkAnalyzer:
    """Оценивает события в скользящем временном окне без блокировки трафика."""

    def __init__(self, rules: NetworkRules | None = None, clock=None):
        self.rules = rules or NetworkRules()
        self.clock = clock or time.monotonic
        self._connections: deque[tuple[float, str, int]] = deque()
        self._dns: deque[float] = deque()
        self._flows: dict[tuple, dict] = {}

    def update_rules(self, rules: NetworkRules) -> None:
        self.rules = rules

    def _prune(self, now: float) -> None:
        cutoff = now - self.rules.window_seconds
        while self._connections and self._connections[0][0] < cutoff:
            self._connections.popleft()
        while self._dns and self._dns[0] < cutoff:
            self._dns.popleft()
        self._flows = {key: value for key, value in self._flows.items() if value["last_time"] >= cutoff}

    def flows(self, limit: int = 100) -> list[dict]:
        """Вернуть агрегированные потоки пакетов за текущее окно."""
        self._prune(self.clock())
        return sorted(self._flows.values(), key=lambda item: item["last_time"], reverse=True)[:limit]

    def analyze_connection(self, connection: ConnectionInfo) -> list[Finding]:
        if not connection.remote_ip:
            return []
        now = self.clock()
        self._prune(now)
        self._connections.append((now, connection.remote_ip, connection.remote_port or 0))
        found = []
        if connection.remote_ip in self.rules.suspicious_ips:
            found.append(Finding("network", "Network.SuspiciousIP", "high", "Адрес в локальном списке", "suspicious_ip"))
        if len(self._connections) >= self.rules.max_connections:
            found.append(Finding("network", "Network.ConnectionBurst", "medium", "Много соединений за короткое время", "connection_burst"))
        if len({ip for _, ip, _ in self._connections}) >= self.rules.max_distinct_ips:
            found.append(Finding("network", "Network.ManyDestinations", "medium", "Много различных IP-адресов", "many_destinations"))
        if sum(1 for _, ip, port in self._connections if (ip, port) == (connection.remote_ip, connection.remote_port or 0)) >= self.rules.max_repeats:
            found.append(Finding("network", "Network.RepeatedConnection", "low", "Повторные подключения к адресу", "repeated_connection"))
        return found

    def analyze_packet(self, packet: PacketInfo) -> list[Finding]:
        now = self.clock()
        self._prune(now)
        key = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port, packet.protocol)
        flow = self._flows.setdefault(key, {"source_ip": packet.source_ip, "source_port": packet.source_port,
                                            "destination_ip": packet.destination_ip,
                                            "destination_port": packet.destination_port,
                                            "protocol": packet.protocol, "packets": 0, "bytes": 0,
                                            "first_seen": packet.observed_at, "last_seen": packet.observed_at,
                                            "last_time": now})
        flow["packets"] += 1
        flow["bytes"] += packet.length
        flow["last_seen"] = packet.observed_at
        flow["last_time"] = now
        if not packet.dns_query:
            return []
        self._dns.append(now)
        found = []
        domain = packet.dns_query.lower()
        if any(domain == suffix.lower().lstrip(".") or domain.endswith("." + suffix.lower().lstrip("."))
               for suffix in self.rules.suspicious_dns_suffixes):
            found.append(Finding("network", "Network.SuspiciousDNS", "high", "Домен в локальном списке", "suspicious_dns"))
        if len(self._dns) >= self.rules.max_dns_queries:
            found.append(Finding("network", "Network.DNSBurst", "medium", "Много DNS-запросов", "dns_burst"))
        return found
