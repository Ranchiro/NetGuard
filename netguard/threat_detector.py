#!/usr/bin/env python3
"""
NetGuard - Threat Detection Module
===================================
ML-based threat detection with signature matching and anomaly detection.
Supports real-time threat identification and automated alerting.

Author: Ruchir Ganatra (@Ranchiro)
License: MIT
"""

import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
import hashlib
import re
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
import threading


class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class ThreatSignature:
    """Represents a threat detection signature."""
    id: str
    name: str
    description: str
    level: ThreatLevel
    pattern: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    enabled: bool = True
    
    def match(self, data: bytes) -> bool:
        """Check if data matches this signature."""
        if not self.enabled:
            return False
        try:
            return bool(re.search(self.pattern.encode(), data))
        except:
            return False


@dataclass 
class ThreatAlert:
    """Represents a detected threat."""
    id: str
    timestamp: datetime
    level: ThreatLevel
    signature_id: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    description: str
    raw_data: bytes = field(default=b'', repr=False)
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'level': self.level.name,
            'signature_id': self.signature_id,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'description': self.description
        }


class AnomalyDetector:
    """
    Statistical anomaly detection using moving averages and standard deviation.
    Detects unusual patterns in network traffic.
    """
    
    def __init__(self, window_size: int = 100, threshold: float = 3.0):
        self.window_size = window_size
        self.threshold = threshold  # Standard deviations
        self.packet_rates = deque(maxlen=window_size)
        self.byte_rates = deque(maxlen=window_size)
        self.connection_counts = deque(maxlen=window_size)
        self.last_update = datetime.now()
    
    def update(self, packets: int, bytes_count: int, connections: int):
        """Update with new measurements."""
        now = datetime.now()
        elapsed = (now - self.last_update).total_seconds()
        if elapsed > 0:
            self.packet_rates.append(packets / elapsed)
            self.byte_rates.append(bytes_count / elapsed)
            self.connection_counts.append(connections)
        self.last_update = now
    
    def _is_anomaly(self, values: deque, current: float) -> Tuple[bool, float]:
        """Check if value is anomalous based on z-score."""
        if len(values) < 10:
            return False, 0.0
        
        mean = np.mean(list(values))
        std = np.std(list(values))
        
        if std == 0:
            return False, 0.0
        
        z_score = abs(current - mean) / std
        return z_score > self.threshold, z_score
    
    def check_packet_rate(self, current_rate: float) -> Tuple[bool, float]:
        """Check if packet rate is anomalous."""
        return self._is_anomaly(self.packet_rates, current_rate)
    
    def check_byte_rate(self, current_rate: float) -> Tuple[bool, float]:
        """Check if byte rate is anomalous."""
        return self._is_anomaly(self.byte_rates, current_rate)
    
    def check_connection_count(self, current: int) -> Tuple[bool, float]:
        """Check if connection count is anomalous."""
        return self._is_anomaly(self.connection_counts, float(current))


class ThreatDetector:
    """
    Main threat detection engine combining signature-based and anomaly detection.
    """
    
    # Default signatures for common attacks
    DEFAULT_SIGNATURES = [
        ThreatSignature('SIG001', 'SQL Injection', 'Potential SQL injection attempt',
                       ThreatLevel.HIGH, r"(union|select|insert|update|delete|drop).*\s+(from|into|table)"),
        ThreatSignature('SIG002', 'XSS Attack', 'Cross-site scripting attempt',
                       ThreatLevel.MEDIUM, r"<script[^>]*>|javascript:"),
        ThreatSignature('SIG003', 'Directory Traversal', 'Path traversal attempt',
                       ThreatLevel.HIGH, r"\.\./|\.\.\\|\.\."),
        ThreatSignature('SIG004', 'Shell Injection', 'Command injection attempt',
                       ThreatLevel.CRITICAL, r";\s*(ls|cat|rm|wget|curl|nc|bash)"),
        ThreatSignature('SIG005', 'Port Scan', 'Potential port scanning activity',
                       ThreatLevel.LOW, r".*", port=0),
        ThreatSignature('SIG006', 'Brute Force', 'Multiple failed authentication',
                       ThreatLevel.MEDIUM, r"(failed|invalid|denied).*login"),
    ]
    
    def __init__(self, enable_anomaly: bool = True):
        self.signatures: Dict[str, ThreatSignature] = {}
        self.alerts: List[ThreatAlert] = []
        self.alert_count = 0
        self.blocked_ips: Set[str] = set()
        self.ip_reputation: Dict[str, int] = defaultdict(int)
        self.anomaly_detector = AnomalyDetector() if enable_anomaly else None
        self._lock = threading.Lock()
        self._alert_callbacks = []
        
        # Load default signatures
        for sig in self.DEFAULT_SIGNATURES:
            self.signatures[sig.id] = sig
        
        logging.info(f'ThreatDetector initialized with {len(self.signatures)} signatures')
    
    def add_signature(self, signature: ThreatSignature):
        """Add a custom threat signature."""
        self.signatures[signature.id] = signature
    
    def remove_signature(self, sig_id: str):
        """Remove a signature by ID."""
        if sig_id in self.signatures:
            del self.signatures[sig_id]
    
    def add_alert_callback(self, callback):
        """Register callback for alert notifications."""
        self._alert_callbacks.append(callback)
    
    def block_ip(self, ip: str):
        """Add IP to blocklist."""
        self.blocked_ips.add(ip)
    
    def unblock_ip(self, ip: str):
        """Remove IP from blocklist."""
        self.blocked_ips.discard(ip)
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips
    
    def analyze(self, packet) -> List[ThreatAlert]:
        """
        Analyze a packet for threats.
        Returns list of detected threats.
        """
        alerts = []
        
        # Check if source is blocked
        if self.is_blocked(packet.src_ip):
            return alerts
        
        # Signature-based detection
        if packet.payload:
            for sig_id, sig in self.signatures.items():
                if sig.match(packet.payload):
                    alert = self._create_alert(sig, packet)
                    alerts.append(alert)
                    self._handle_alert(alert)
        
        # Update IP reputation
        self.ip_reputation[packet.src_ip] += len(alerts)
        
        # Auto-block high reputation score IPs
        if self.ip_reputation[packet.src_ip] > 100:
            self.block_ip(packet.src_ip)
        
        return alerts
    
    def _create_alert(self, sig: ThreatSignature, packet) -> ThreatAlert:
        """Create a threat alert."""
        self.alert_count += 1
        alert_id = hashlib.md5(f'{self.alert_count}{datetime.now()}'.encode()).hexdigest()[:12]
        
        return ThreatAlert(
            id=alert_id,
            timestamp=datetime.now(),
            level=sig.level,
            signature_id=sig.id,
            source_ip=packet.src_ip,
            dest_ip=packet.dst_ip,
            source_port=packet.src_port,
            dest_port=packet.dst_port,
            protocol=packet.protocol,
            description=f'{sig.name}: {sig.description}',
            raw_data=packet.payload[:1000] if packet.payload else b''
        )
    
    def _handle_alert(self, alert: ThreatAlert):
        """Handle a detected alert."""
        with self._lock:
            self.alerts.append(alert)
            # Keep only last 10000 alerts
            if len(self.alerts) > 10000:
                self.alerts = self.alerts[-10000:]
        
        # Notify callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logging.error(f'Alert callback error: {e}')
    
    def get_alerts(self, level: ThreatLevel = None, limit: int = 100) -> List[ThreatAlert]:
        """Get recent alerts, optionally filtered by level."""
        with self._lock:
            alerts = self.alerts[-limit:]
            if level:
                alerts = [a for a in alerts if a.level.value >= level.value]
            return alerts
    
    def get_statistics(self) -> dict:
        """Get threat detection statistics."""
        with self._lock:
            level_counts = defaultdict(int)
            for alert in self.alerts:
                level_counts[alert.level.name] += 1
            
            return {
                'total_alerts': len(self.alerts),
                'blocked_ips': len(self.blocked_ips),
                'signatures_loaded': len(self.signatures),
                'alerts_by_level': dict(level_counts)
            }


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    detector = ThreatDetector()
    print(f'Threat Detector initialized')
    print(f'Loaded {len(detector.signatures)} signatures')
    print(f'Statistics: {detector.get_statistics()}')
