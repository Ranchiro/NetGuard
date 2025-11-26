#!/usr/bin/env python3
"""
NetGuard - Packet Analyzer Module
================================
Deep packet inspection and protocol analysis for network traffic monitoring.
Supports TCP, UDP, ICMP, HTTP, DNS, and custom protocol analysis.

Author: Ruchir Ganatra (@Ranchiro)
License: MIT
"""

import socket
import struct
import threading
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Callable
import ipaddress
import hashlib
import json


class PacketHeader:
    """Represents parsed packet header information."""
    
    def __init__(self):
        self.timestamp = datetime.now()
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = None
        self.length = 0
        self.flags = {}
        self.payload = b''
        self.raw_data = b''
    
    def to_dict(self) -> dict:
        """Convert header to dictionary representation."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'length': self.length,
            'flags': self.flags
        }
    
    def get_flow_id(self) -> str:
        """Generate unique flow identifier."""
        flow_tuple = f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"
        return hashlib.md5(flow_tuple.encode()).hexdigest()[:16]


class PacketAnalyzer:
    """
    Advanced packet analyzer with deep packet inspection capabilities.
    Supports multiple protocols and provides real-time analysis.
    """
    
    # Protocol numbers
    PROTOCOL_ICMP = 1
    PROTOCOL_TCP = 6
    PROTOCOL_UDP = 17
    
    # Common ports
    WELL_KNOWN_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-ALT'
    }
    
    def __init__(self, interface: str = None, promiscuous: bool = True):
        """
        Initialize the packet analyzer.
        
        Args:
            interface: Network interface to capture on
            promiscuous: Enable promiscuous mode
        """
        self.interface = interface
        self.promiscuous = promiscuous
        self.socket = None
        self.running = False
        self.packet_count = 0
        self.byte_count = 0
        self.callbacks: List[Callable] = []
        self.filters: List[Callable] = []
        self.statistics = defaultdict(int)
        self.flow_table: Dict[str, dict] = {}
        self._lock = threading.Lock()
    
    def add_callback(self, callback: Callable[[PacketHeader], None]):
        """Register a callback for packet processing."""
        self.callbacks.append(callback)
    
    def add_filter(self, filter_func: Callable[[PacketHeader], bool]):
        """Add a packet filter. Packets not matching are discarded."""
        self.filters.append(filter_func)
    
    def _parse_ethernet_header(self, data: bytes) -> Tuple[str, str, int]:
        """Parse Ethernet frame header."""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = eth_header[2]
        return dest_mac, src_mac, eth_type
    
    def _parse_ip_header(self, data: bytes) -> PacketHeader:
        """Parse IPv4 header and extract information."""
        packet = PacketHeader()
        packet.raw_data = data
        
        # IP header (minimum 20 bytes)
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        
        packet.length = ip_header[2]
        ttl = ip_header[5]
        protocol = ip_header[6]
        packet.protocol = self._get_protocol_name(protocol)
        packet.src_ip = socket.inet_ntoa(ip_header[8])
        packet.dst_ip = socket.inet_ntoa(ip_header[9])
        
        # Parse transport layer
        transport_data = data[ihl:]
        if protocol == self.PROTOCOL_TCP:
            self._parse_tcp_header(transport_data, packet)
        elif protocol == self.PROTOCOL_UDP:
            self._parse_udp_header(transport_data, packet)
        elif protocol == self.PROTOCOL_ICMP:
            self._parse_icmp_header(transport_data, packet)
        
        return packet
    
    def _parse_tcp_header(self, data: bytes, packet: PacketHeader):
        """Parse TCP header and flags."""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        packet.src_port = tcp_header[0]
        packet.dst_port = tcp_header[1]
        
        flags = tcp_header[5]
        packet.flags = {
            'FIN': bool(flags & 0x01),
            'SYN': bool(flags & 0x02),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'ACK': bool(flags & 0x10),
            'URG': bool(flags & 0x20)
        }
        
        data_offset = (tcp_header[4] >> 4) * 4
        packet.payload = data[data_offset:]
    
    def _parse_udp_header(self, data: bytes, packet: PacketHeader):
        """Parse UDP header."""
        udp_header = struct.unpack('!HHHH', data[:8])
        packet.src_port = udp_header[0]
        packet.dst_port = udp_header[1]
        packet.payload = data[8:]
    
    def _parse_icmp_header(self, data: bytes, packet: PacketHeader):
        """Parse ICMP header."""
        icmp_header = struct.unpack('!BBH', data[:4])
        packet.flags = {
            'type': icmp_header[0],
            'code': icmp_header[1]
        }
        packet.payload = data[4:]
    
    def _get_protocol_name(self, protocol: int) -> str:
        """Convert protocol number to name."""
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP'}
        return protocols.get(protocol, f'UNKNOWN({protocol})')
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for well-known ports."""
        return self.WELL_KNOWN_PORTS.get(port, 'UNKNOWN')
    
    def _update_statistics(self, packet: PacketHeader):
        """Update traffic statistics."""
        with self._lock:
            self.packet_count += 1
            self.byte_count += packet.length
            self.statistics[f'protocol_{packet.protocol}'] += 1
            if packet.src_port:
                self.statistics[f'port_{packet.dst_port}'] += 1
            
            # Update flow table
            flow_id = packet.get_flow_id()
            if flow_id not in self.flow_table:
                self.flow_table[flow_id] = {
                    'first_seen': packet.timestamp,
                    'packets': 0,
                    'bytes': 0
                }
            self.flow_table[flow_id]['packets'] += 1
            self.flow_table[flow_id]['bytes'] += packet.length
            self.flow_table[flow_id]['last_seen'] = packet.timestamp
    
    def analyze_packet(self, raw_data: bytes) -> Optional[PacketHeader]:
        """Analyze a single packet and return parsed header."""
        try:
            # Parse IP packet (skip Ethernet if present)
            if len(raw_data) < 20:
                return None
            
            packet = self._parse_ip_header(raw_data)
            
            # Apply filters
            for filter_func in self.filters:
                if not filter_func(packet):
                    return None
            
            # Update statistics
            self._update_statistics(packet)
            
            # Call registered callbacks
            for callback in self.callbacks:
                callback(packet)
            
            return packet
            
        except Exception as e:
            return None
    
    def get_statistics(self) -> dict:
        """Get current traffic statistics."""
        with self._lock:
            return {
                'total_packets': self.packet_count,
                'total_bytes': self.byte_count,
                'active_flows': len(self.flow_table),
                'protocol_distribution': dict(self.statistics)
            }
    
    def get_top_talkers(self, n: int = 10) -> List[dict]:
        """Get top N hosts by traffic volume."""
        host_traffic = defaultdict(int)
        for flow_id, flow_data in self.flow_table.items():
            host_traffic[flow_id] += flow_data['bytes']
        
        sorted_hosts = sorted(host_traffic.items(), key=lambda x: x[1], reverse=True)
        return [{'flow': h, 'bytes': b} for h, b in sorted_hosts[:n]]


class DeepPacketInspector:
    """
    Deep Packet Inspection for application layer analysis.
    Detects protocols and extracts application-level data.
    """
    
    # HTTP patterns
    HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS']
    
    # DNS constants
    DNS_PORT = 53
    
    def __init__(self):
        self.detected_apps = defaultdict(int)
    
    def inspect(self, packet: PacketHeader) -> dict:
        """Perform deep packet inspection."""
        result = {'app_protocol': 'unknown', 'details': {}}
        
        if not packet.payload:
            return result
        
        # Check for HTTP
        if self._is_http(packet):
            result['app_protocol'] = 'HTTP'
            result['details'] = self._parse_http(packet.payload)
        
        # Check for DNS
        elif packet.dst_port == self.DNS_PORT or packet.src_port == self.DNS_PORT:
            result['app_protocol'] = 'DNS'
            result['details'] = self._parse_dns(packet.payload)
        
        # Check for TLS/SSL
        elif self._is_tls(packet.payload):
            result['app_protocol'] = 'TLS'
            result['details'] = self._parse_tls(packet.payload)
        
        self.detected_apps[result['app_protocol']] += 1
        return result
    
    def _is_http(self, packet: PacketHeader) -> bool:
        """Check if payload contains HTTP data."""
        if not packet.payload:
            return False
        for method in self.HTTP_METHODS:
            if packet.payload.startswith(method):
                return True
        return packet.payload.startswith(b'HTTP/')
    
    def _is_tls(self, payload: bytes) -> bool:
        """Check if payload is TLS handshake."""
        if len(payload) < 5:
            return False
        return payload[0] == 0x16 and payload[1:3] == b'\x03\x01'
    
    def _parse_http(self, payload: bytes) -> dict:
        """Parse HTTP request/response."""
        try:
            lines = payload.split(b'\r\n')
            first_line = lines[0].decode('utf-8', errors='ignore')
            headers = {}
            for line in lines[1:]:
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.decode()] = value.strip().decode()
            return {'first_line': first_line, 'headers': headers}
        except:
            return {}
    
    def _parse_dns(self, payload: bytes) -> dict:
        """Parse DNS query/response."""
        try:
            # Transaction ID (2 bytes) + Flags (2 bytes)
            flags = struct.unpack('!H', payload[2:4])[0]
            qr = (flags >> 15) & 1
            return {'type': 'response' if qr else 'query'}
        except:
            return {}
    
    def _parse_tls(self, payload: bytes) -> dict:
        """Parse TLS record."""
        try:
            content_type = payload[0]
            version = struct.unpack('!H', payload[1:3])[0]
            return {'content_type': content_type, 'version': hex(version)}
        except:
            return {}


if __name__ == '__main__':
    print('NetGuard Packet Analyzer Module')
    print('================================')
    analyzer = PacketAnalyzer()
    print(f'Analyzer initialized. Ready for packet capture.')
    print(f'Statistics: {analyzer.get_statistics()}')
