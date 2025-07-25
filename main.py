"""
Wi-Fi Network Scanner App

Features:
- Scans all devices on the Wi-Fi network (IP, MAC, vendor, hostname)
- Tracks device uptime
- Estimates location (distance from router) using RSSI
- GUI dashboard (sortable table, numeric distances, radar visualization)
- Logs to SQLite
- Auto-refreshes every 5 seconds
- Standalone, ready for PyInstaller

Dependencies:
- Python 3.11+
- scapy
- pywifi
- requests
- PyQt5
- sqlite3 (standard)

Instructions:
1. Install dependencies:
   pip install scapy pywifi requests PyQt5
2. Run: python main.py
3. To build .exe: see build.bat
"""

import sys
import os
import time
import math
import threading
import sqlite3
import socket
import requests
from datetime import datetime
from collections import defaultdict

from scapy.all import ARP, Ether, srp, conf
import pywifi
from pywifi import const

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QHeaderView, QLabel, QHBoxLayout, QPushButton, QComboBox, QAbstractItemView, QFrame
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPainter, QColor, QPen

# --- CONFIG ---
DEFAULT_SUBNET = '192.168.1.0/24'
DB_FILE = 'devices.db'
VENDOR_API = 'https://api.macvendors.com/'
REFRESH_INTERVAL = 5  # seconds
WIFI_INTERFACE = None  # None = auto-detect

# --- UTILS ---
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''

def get_vendor(mac):
    try:
        resp = requests.get(VENDOR_API + mac, timeout=2)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return ''

def rssi_to_distance(rssi, freq_mhz):
    # Path loss model
    # distance (m) ≈ 10 ^ ((27.55 - (20 * log10(frequency in MHz)) + |RSSI|) / 20)
    try:
        return round(10 ** ((27.55 - (20 * math.log10(freq_mhz)) + abs(rssi)) / 20), 2)
    except Exception:
        return -1

def get_wifi_interface():
    wifi = pywifi.PyWiFi()
    if WIFI_INTERFACE is not None:
        for iface in wifi.interfaces():
            if iface.name() == WIFI_INTERFACE:
                return iface
    return wifi.interfaces()[0] if wifi.interfaces() else None

# --- DATABASE ---
class DeviceTracker:
    def __init__(self, db_file=DB_FILE):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self._init_db()
        self.lock = threading.Lock()

    def _init_db(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            first_seen INTEGER,
            last_seen INTEGER,
            total_uptime INTEGER
        )''')
        self.conn.commit()

    def log_device(self, mac, ip, hostname, vendor):
        now = int(time.time())
        with self.lock:
            c = self.conn.cursor()
            c.execute('SELECT first_seen, last_seen, total_uptime FROM devices WHERE mac=?', (mac,))
            row = c.fetchone()
            if row:
                first_seen, last_seen, total_uptime = row
                # Update last_seen and total_uptime
                if now > last_seen:
                    total_uptime += now - last_seen
                c.execute('''UPDATE devices SET ip=?, hostname=?, vendor=?, last_seen=?, total_uptime=? WHERE mac=?''',
                          (ip, hostname, vendor, now, total_uptime, mac))
            else:
                c.execute('''INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, total_uptime) VALUES (?, ?, ?, ?, ?, ?, 0)''',
                          (mac, ip, hostname, vendor, now, now))
            self.conn.commit()

    def get_uptime(self, mac):
        with self.lock:
            c = self.conn.cursor()
            c.execute('SELECT first_seen, last_seen, total_uptime FROM devices WHERE mac=?', (mac,))
            row = c.fetchone()
            if row:
                first_seen, last_seen, total_uptime = row
                # Add current session uptime
                now = int(time.time())
                if now > last_seen:
                    total_uptime += now - last_seen
                return total_uptime, first_seen
            return 0, None

    def close(self):
        self.conn.close()

# --- NETWORK SCANNER ---
class NetworkScanner:
    def __init__(self, subnet=DEFAULT_SUBNET, tracker=None):
        self.subnet = subnet
        self.tracker = tracker
        self.vendor_cache = {}

    def scan(self):
        # ARP scan
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.subnet)
        ans, _ = srp(pkt, timeout=2, retry=1)
        devices = []
        for snd, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc
            hostname = get_hostname(ip)
            if mac in self.vendor_cache:
                vendor = self.vendor_cache[mac]
            else:
                vendor = get_vendor(mac)
                self.vendor_cache[mac] = vendor
            if self.tracker:
                self.tracker.log_device(mac, ip, hostname, vendor)
                uptime, first_seen = self.tracker.get_uptime(mac)
            else:
                uptime, first_seen = 0, None
            devices.append({
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'uptime': uptime,
                'first_seen': first_seen
            })
        return devices

# --- LOCATION ESTIMATOR ---
class LocationEstimator:
    def __init__(self):
        self.iface = get_wifi_interface()
        self.freq_mhz = None
        if self.iface:
            self.freq_mhz = self._get_freq()

    def _get_freq(self):
        # Try to get frequency of current connection
        try:
            profile = self.iface.network_profile()
            if hasattr(profile, 'frequency'):
                return profile.frequency
        except Exception:
            pass
        # Default to 2412 MHz (channel 1)
        return 2412

    def get_rssi_map(self):
        # Returns {mac: rssi}
        rssi_map = {}
        if not self.iface:
            return rssi_map
        self.iface.scan()
        time.sleep(1.5)  # Wait for scan
        results = self.iface.scan_results()
        for net in results:
            if hasattr(net, 'bssid') and hasattr(net, 'signal'):
                rssi_map[net.bssid.lower()] = net.signal
        return rssi_map

    def get_distance(self, mac, rssi=None):
        if rssi is None:
            return -1
        freq = self.freq_mhz or 2412
        return rssi_to_distance(rssi, freq)

# --- GUI ---
class RadarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = []  # List of (distance, mac, label)
        self.setMinimumSize(300, 300)

    def set_devices(self, devices):
        self.devices = devices
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        w, h = self.width(), self.height()
        center = (w // 2, h // 2)
        max_radius = min(w, h) // 2 - 20
        # Draw radar circles
        for i in range(1, 5):
            painter.setPen(QPen(QColor(180, 180, 180), 1, Qt.DashLine))
            painter.drawEllipse(center[0] - i*max_radius//4, center[1] - i*max_radius//4, 2*i*max_radius//4, 2*i*max_radius//4)
        # Draw router at center
        painter.setPen(QPen(Qt.black, 2))
        painter.setBrush(QColor(0, 128, 255))
        painter.drawEllipse(center[0] - 8, center[1] - 8, 16, 16)
        painter.drawText(center[0] + 10, center[1], "Router")
        # Draw devices
        for idx, (distance, mac, label) in enumerate(self.devices):
            # Map distance to radius (max 20m)
            r = min(distance, 20) / 20 * max_radius
            angle = 2 * math.pi * idx / max(1, len(self.devices))
            x = int(center[0] + r * math.cos(angle))
            y = int(center[1] + r * math.sin(angle))
            painter.setPen(QPen(Qt.darkGreen, 2))
            painter.setBrush(QColor(0, 255, 0, 180))
            painter.drawEllipse(x - 6, y - 6, 12, 12)
            painter.drawText(x + 8, y, label)

class WiFiDashboard(QMainWindow):
    def __init__(self, scanner, locator, tracker, subnet=DEFAULT_SUBNET):
        super().__init__()
        self.setWindowTitle("Wi-Fi Network Scanner")
        self.scanner = scanner
        self.locator = locator
        self.tracker = tracker
        self.subnet = subnet
        self.sort_col = 0
        self.sort_order = Qt.AscendingOrder
        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(REFRESH_INTERVAL * 1000)
        self.refresh()

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        # Controls
        ctrl_layout = QHBoxLayout()
        self.subnet_box = QComboBox()
        self.subnet_box.setEditable(True)
        self.subnet_box.addItem(self.subnet)
        self.subnet_box.setEditText(self.subnet)
        ctrl_layout.addWidget(QLabel("Subnet:"))
        ctrl_layout.addWidget(self.subnet_box)
        self.refresh_btn = QPushButton("Scan Now")
        self.refresh_btn.clicked.connect(self.refresh)
        ctrl_layout.addWidget(self.refresh_btn)
        ctrl_layout.addStretch()
        main_layout.addLayout(ctrl_layout)
        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "IP", "MAC", "Hostname", "Vendor", "Uptime", "Distance (m)", "RSSI (dBm)"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().sectionClicked.connect(self.sort_table)
        main_layout.addWidget(self.table)
        # Radar
        self.radar = RadarWidget()
        main_layout.addWidget(QLabel("Radar View (approximate)"))
        main_layout.addWidget(self.radar)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        self.resize(900, 700)

    def sort_table(self, col):
        self.sort_col = col
        self.sort_order = self.table.horizontalHeader().sortIndicatorOrder()
        self.table.sortItems(col, self.sort_order)

    def refresh(self):
        subnet = self.subnet_box.currentText().strip()
        if subnet != self.scanner.subnet:
            self.scanner.subnet = subnet
        devices = self.scanner.scan()
        rssi_map = self.locator.get_rssi_map()
        table_data = []
        radar_data = []
        for dev in devices:
            mac = dev['mac'].lower()
            rssi = rssi_map.get(mac, None)
            distance = self.locator.get_distance(mac, rssi) if rssi is not None else -1
            uptime = dev['uptime']
            uptime_str = self.format_uptime(uptime)
            table_data.append([
                dev['ip'],
                dev['mac'],
                dev['hostname'],
                dev['vendor'],
                uptime_str,
                f"{distance if distance >= 0 else 'N/A'}",
                f"{rssi if rssi is not None else 'N/A'}"
            ])
            if distance >= 0:
                radar_data.append((distance, mac, dev['hostname'] or dev['ip']))
        self.update_table(table_data)
        self.radar.set_devices(radar_data)

    def update_table(self, data):
        self.table.setRowCount(len(data))
        for row, rowdata in enumerate(data):
            for col, val in enumerate(rowdata):
                item = QTableWidgetItem(str(val))
                if col == 5:  # Distance
                    try:
                        v = float(val)
                        item.setData(Qt.EditRole, v)
                    except Exception:
                        pass
                self.table.setItem(row, col, item)
        self.table.sortItems(self.sort_col, self.sort_order)

    @staticmethod
    def format_uptime(seconds):
        if not seconds:
            return "0s"
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        parts = []
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        if m: parts.append(f"{m}m")
        if s: parts.append(f"{s}s")
        return ' '.join(parts)

# --- MAIN ---
def main():
    if os.geteuid() != 0:
        print("[!] Please run as root/administrator for network scanning.")
        sys.exit(1)
    tracker = DeviceTracker(DB_FILE)
    scanner = NetworkScanner(DEFAULT_SUBNET, tracker)
    locator = LocationEstimator()
    app = QApplication(sys.argv)
    dashboard = WiFiDashboard(scanner, locator, tracker)
    dashboard.show()
    app.exec_()
    tracker.close()

if __name__ == '__main__':
    main()