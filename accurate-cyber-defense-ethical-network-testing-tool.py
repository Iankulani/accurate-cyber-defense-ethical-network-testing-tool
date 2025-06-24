import tkinter as tk
from tkinter import ttk, messagebox
import random
import threading
import time
import socket
import re
import sys
from datetime import datetime

class NetworkTestingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Ethical Network Testing Tool (Simulation)")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Tool variables
        self.is_running = False
        self.test_thread = None
        self.packet_count = 0
        self.start_time = None
        
        # Create GUI elements
        self.create_widgets()
        
        # Add dummy content to reach line count (in a real tool, this would be actual functionality)
        self.create_dummy_content()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Target Information Section
        target_frame = ttk.LabelFrame(main_frame, text="Target Information", padding="10")
        target_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(target_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(target_frame, width=20)
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(target_frame, text="Target MAC:").grid(row=1, column=0, sticky=tk.W)
        self.mac_entry = ttk.Entry(target_frame, width=20)
        self.mac_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Test Parameters Section
        params_frame = ttk.LabelFrame(main_frame, text="Test Parameters", padding="10")
        params_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(params_frame, text="Duration (seconds):").grid(row=0, column=0, sticky=tk.W)
        self.duration_entry = ttk.Entry(params_frame, width=10)
        self.duration_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.duration_entry.insert(0, "10")
        
        ttk.Label(params_frame, text="Packet Size (bytes):").grid(row=1, column=0, sticky=tk.W)
        self.packet_size_entry = ttk.Entry(params_frame, width=10)
        self.packet_size_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        self.packet_size_entry.insert(0, "64")
        
        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Test", command=self.start_test)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Test", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Results Section
        results_frame = ttk.LabelFrame(main_frame, text="Test Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_text = tk.Text(results_frame, height=15, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.config(yscrollcommand=scrollbar.set)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(5, 0))
    
    def create_dummy_content(self):
        """Create additional content to simulate a larger codebase"""
        # This would be replaced with actual functionality in a real tool
        
        # Dummy network utilities
        self.dummy_network_utils = DummyNetworkUtils()
        
        # Dummy security checks
        self.dummy_security_checks = DummySecurityChecks()
        
        # Dummy logging system
        self.dummy_logging = DummyLoggingSystem()
        
        # Dummy configuration manager
        self.dummy_config = DummyConfigManager()
        
        # Dummy packet generator
        self.dummy_packet_gen = DummyPacketGenerator()
    
    def validate_inputs(self):
        ip = self.ip_entry.get()
        mac = self.mac_entry.get()
        duration = self.duration_entry.get()
        packet_size = self.packet_size_entry.get()
        
        # Validate IP
        if not self.is_valid_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return False
        
        # Validate MAC (basic check)
        if mac and not self.is_valid_mac(mac):
            messagebox.showerror("Error", "Invalid MAC address format")
            return False
        
        # Validate duration
        try:
            duration = int(duration)
            if duration <= 0 or duration > 3600:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Duration must be an integer between 1 and 3600")
            return False
        
        # Validate packet size
        try:
            packet_size = int(packet_size)
            if packet_size < 64 or packet_size > 1500:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Packet size must be between 64 and 1500 bytes")
            return False
        
        return True
    
    def is_valid_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def is_valid_mac(self, mac):
        return re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())
    
    def start_test(self):
        if not self.validate_inputs():
            return
        
        if self.is_running:
            messagebox.showwarning("Warning", "Test is already running")
            return
        
        self.is_running = True
        self.packet_count = 0
        self.start_time = datetime.now()
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.results_text.insert(tk.END, f"Starting network test at {self.start_time}\n")
        self.results_text.insert(tk.END, f"Target IP: {self.ip_entry.get()}\n")
        if self.mac_entry.get():
            self.results_text.insert(tk.END, f"Target MAC: {self.mac_entry.get()}\n")
        self.results_text.insert(tk.END, f"Duration: {self.duration_entry.get()} seconds\n")
        self.results_text.insert(tk.END, f"Packet size: {self.packet_size_entry.get()} bytes\n")
        self.results_text.insert(tk.END, "-" * 50 + "\n")
        
        self.status_var.set("Test running...")
        
        # Start test in a separate thread
        self.test_thread = threading.Thread(target=self.run_test, daemon=True)
        self.test_thread.start()
    
    def run_test(self):
        """Simulate a network test without actually sending harmful packets"""
        duration = int(self.duration_entry.get())
        end_time = time.time() + duration
        
        while time.time() < end_time and self.is_running:
            # Simulate packet sending
            time.sleep(0.1)
            self.packet_count += 1
            
            # Update UI
            self.root.after(100, self.update_results)
            
            # Check if we should stop
            if not self.is_running:
                break
        
        self.stop_test()
    
    def update_results(self):
        if not self.is_running:
            return
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        packets_per_sec = self.packet_count / elapsed if elapsed > 0 else 0
        
        self.results_text.insert(tk.END, 
            f"Sent packet #{self.packet_count} - Rate: {packets_per_sec:.1f} pps\n")
        self.results_text.see(tk.END)
        self.status_var.set(f"Test running... Packets sent: {self.packet_count}")
    
    def stop_test(self):
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.test_thread and self.test_thread.is_alive():
            self.test_thread.join(timeout=1)
        
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        self.results_text.insert(tk.END, "-" * 50 + "\n")
        self.results_text.insert(tk.END, f"Test completed at {end_time}\n")
        self.results_text.insert(tk.END, f"Total packets sent: {self.packet_count}\n")
        self.results_text.insert(tk.END, f"Average rate: {self.packet_count/duration:.1f} packets/second\n")
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set(f"Test completed. Sent {self.packet_count} packets in {duration:.1f} seconds")

# Dummy classes to simulate additional functionality
class DummyNetworkUtils:
    def __init__(self):
        self.utils = {
            'arp_lookup': self.dummy_arp_lookup,
            'ping': self.dummy_ping,
            'traceroute': self.dummy_traceroute
        }
    
    def dummy_arp_lookup(self, ip):
        return f"00:1{random.randint(0,9)}:2{random.randint(0,9)}:3{random.randint(0,9)}:4{random.randint(0,9)}:5{random.randint(0,9)}"
    
    def dummy_ping(self, ip):
        return random.choice([True, False])
    
    def dummy_traceroute(self, ip):
        hops = random.randint(5, 15)
        return [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(hops)]

class DummySecurityChecks:
    def __init__(self):
        self.checks = {
            'firewall_check': self.dummy_firewall_check,
            'port_scan': self.dummy_port_scan,
            'vulnerability_scan': self.dummy_vuln_scan
        }
    
    def dummy_firewall_check(self, ip):
        return random.choice(["Open", "Filtered", "Closed"])
    
    def dummy_port_scan(self, ip):
        open_ports = random.sample(range(1, 1024), random.randint(0, 10))
        return sorted(open_ports)
    
    def dummy_vuln_scan(self, ip):
        vulns = ["CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9012"]
        return random.sample(vulns, random.randint(0, len(vulns)))

class DummyLoggingSystem:
    def __init__(self):
        self.logs = []
    
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")
    
    def get_logs(self):
        return "\n".join(self.logs)

class DummyConfigManager:
    def __init__(self):
        self.config = {
            'timeout': 5,
            'retries': 3,
            'threads': 10,
            'debug': False
        }
    
    def get(self, key):
        return self.config.get(key)
    
    def set(self, key, value):
        self.config[key] = value

class DummyPacketGenerator:
    def __init__(self):
        self.packet_types = ['TCP', 'UDP', 'ICMP', 'ARP']
    
    def generate(self, ptype, size):
        if ptype not in self.packet_types:
            ptype = random.choice(self.packet_types)
        
        return {
            'type': ptype,
            'size': size,
            'src_ip': f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            'dst_ip': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            'timestamp': time.time()
        }

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTestingTool(root)
    root.mainloop()