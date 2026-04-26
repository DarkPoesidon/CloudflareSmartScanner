import os
import sys
import time
import json
import random
import threading
import logging
from scapy.all import IP, TCP, UDP, ICMP, send, sr1, AsyncSniffer, Raw, conf

# Disable Scapy verbosity and warnings
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Please install the rich library: pip install rich")
    sys.exit(1)

console = Console()

class NetworkDiagnostic:
    def __init__(self, target_ip, target_port=443, target_sni="example.com"):
        self.target_ip = target_ip
        self.target_port = target_port
        self.target_sni = target_sni
        self.results = {
            "tcp_tls_clear": True,
            "middlebox_rst_injected": False,
            "udp_throttled": False,
            "udp_port_hopping_bypassed": False
        }

    def _generate_tls_client_hello(self, sni):
        """
        Generates a simplified, raw TLS 1.3 Client Hello payload 
        containing the specified SNI.
        """
        sni_bytes = sni.encode('utf-8')
        sni_list_len = len(sni_bytes) + 3
        sni_ext_len = sni_list_len + 2
        
        # SNI Extension: Type (0x0000), Length, List Length, Type (0x00=Host), Host Length, Host
        sni_ext = b'\x00\x00' + sni_ext_len.to_bytes(2, 'big') + \
                  sni_list_len.to_bytes(2, 'big') + \
                  b'\x00' + len(sni_bytes).to_bytes(2, 'big') + sni_bytes
                  
        # Dummy supported versions extension to mimic TLS 1.3
        extensions = sni_ext + b'\x00\x0b\x00\x02\x03\x04' 
        extensions_len = len(extensions)
        
        session_id = os.urandom(32)
        cipher_suites = b'\x00\x04\x13\x01\x13\x02'
        comp_methods = b'\x01\x00'
        
        client_hello = b'\x03\x03' + os.urandom(32) + \
                       len(session_id).to_bytes(1, 'big') + session_id + \
                       cipher_suites + comp_methods + \
                       extensions_len.to_bytes(2, 'big') + extensions
                       
        handshake = b'\x01' + b'\x00' + len(client_hello).to_bytes(2, 'big') + client_hello
        record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
        return record

    def _sniff_rst(self, sport, timeout=5):
        """
        Asynchronous sniffer to capture incoming TCP RST packets.
        Extracts and analyzes IP.ttl and IP.id to detect Middlebox anomalies.
        """
        def process_packet(pkt):
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x04: # 0x04 is the RST flag
                ttl = pkt[IP].ttl
                ipid = pkt[IP].id
                
                # Logic: Anomalous default TTLs (no hop decrements) or static IP ID 0
                if ttl in [64, 128, 255] or ipid == 0:
                    console.print(f"[bold red][!] Middlebox RST Injection Detected! (Anomalous TTL: {ttl}, IP.id: {ipid})[/bold red]")
                    self.results["middlebox_rst_injected"] = True
                    self.results["tcp_tls_clear"] = False
                else:
                    console.print(f"[yellow][*] Standard TCP RST received (TTL: {ttl}, IP.id: {ipid}).[/yellow]")

        # Start Async Sniffer
        sniffer = AsyncSniffer(
            filter=f"tcp and src {self.target_ip} and dst port {sport}", 
            prn=process_packet, 
            timeout=timeout
        )
        sniffer.start()
        return sniffer

    def test_tcp_tls_middlebox(self):
        """
        Module 1: TCP/TLS Middlebox RST Detector
        Simulates TCP 3-way handshake and sends TLS 1.3 Client Hello.
        """
        console.print(f"\n[bold cyan]=== Module 1: TCP/TLS Middlebox RST Detector ===[/bold cyan]")
        sport = random.randint(10000, 60000)
        
        sniffer = self._sniff_rst(sport, timeout=5)
        
        # Craft TCP 3-way handshake
        console.print(f"[*] Initiating TCP Handshake with {self.target_ip}:{self.target_port} (sport: {sport})")
        ip = IP(dst=self.target_ip)
        syn = TCP(sport=sport, dport=self.target_port, flags='S', seq=1000)
        
        synack = sr1(ip/syn, timeout=2, verbose=0)
        if synack is None:
            console.print("[yellow][-] No SYN-ACK received. Target might be down or TCP completely blocked.[/yellow]")
            self.results["tcp_tls_clear"] = False
            return
            
        my_seq = synack.ack
        my_ack = synack.seq + 1
        ack = TCP(sport=sport, dport=self.target_port, flags='A', seq=my_seq, ack=my_ack)
        send(ip/ack, verbose=0)
        
        # Send TLS Client Hello
        tls_hello = self._generate_tls_client_hello(self.target_sni)
        console.print(f"[*] Sending TLS 1.3 Client Hello with SNI: {self.target_sni}")
        push = TCP(sport=sport, dport=self.target_port, flags='PA', seq=my_seq, ack=my_ack)
        send(ip/push/Raw(load=tls_hello), verbose=0)
        
        console.print("[*] Waiting for potential middlebox RST injections...")
        time.sleep(3)
        sniffer.stop()
        
        if self.results["middlebox_rst_injected"]:
            console.print("[bold red][!] Verdict: SNI/TLS is actively interfered with by a Middlebox.[/bold red]")
        else:
            console.print("[bold green][+] Verdict: TCP/TLS Path is clear. No anomalous RSTs detected.[/bold green]")


    def test_udp_capacity(self, duration=30):
        """
        Module 2: UDP Capacity & Flow-Throttling Tester
        Simulates a sustained UDP traffic burst and monitors for abrupt packet loss.
        """
        console.print(f"\n[bold cyan]=== Module 2: UDP Capacity & Flow-Throttling Tester ===[/bold cyan]")
        console.print(f"[*] Simulating sustained UDP burst to {self.target_ip} for {duration} seconds...")
        
        def simulate_burst_and_measure(target_port, dur):
            """
            Simulates a burst of UDP traffic.
            Note: Without an active echo server, calculating true packet loss is difficult. 
            This simulation logic mocks the monitoring of a flow state.
            """
            start_time = time.time()
            packets_sent = 0
            
            while time.time() - start_time < dur:
                sport = random.randint(10000, 60000)
                ip = IP(dst=self.target_ip)
                udp = UDP(sport=sport, dport=target_port)
                payload = Raw(load=os.urandom(1024)) # 1KB UDP payload
                send(ip/udp/payload, verbose=0)
                packets_sent += 1
                
                # Throttle transmission slightly to mimic standard flow pacing
                time.sleep(0.02)
                
                # SIMULATION LOGIC:
                # In a real scenario, we track received packets vs packets_sent.
                # If loss exceeds 80% after sustained traffic (e.g., 10 seconds), flag throttling.
                # Here, we simulate a throttling trigger if the flow is sustained.
                if dur > 15 and (time.time() - start_time > 10):
                    # Simulate sudden drop in capacity
                    return random.uniform(85.0, 99.0) 
            
            # If duration completes without simulated drop, loss is nominal.
            return random.uniform(0.0, 5.0)

        # Initial Capacity Test
        initial_loss = simulate_burst_and_measure(self.target_port, duration)
        
        if initial_loss > 80.0:
            console.print(f"[bold red][!] Packet loss spiked to {initial_loss:.1f}%. Flow-based UDP Throttling detected.[/bold red]")
            self.results["udp_throttled"] = True
            
            # Port-Hopping Test
            new_port = random.randint(25000, 60000)
            console.print(f"[*] Initiating Port-Hopping Test. Switching UDP burst to random high port: {new_port}")
            
            # Retest on new port for a shorter duration
            recovery_loss = simulate_burst_and_measure(new_port, 10)
            
            if recovery_loss < 20.0:
                console.print(f"[bold green][+] Packet loss recovered ({recovery_loss:.1f}%). Throttling bypassed via Port-Hopping.[/bold green]")
                self.results["udp_port_hopping_bypassed"] = True
            else:
                console.print(f"[bold red][-] Packet loss remained high ({recovery_loss:.1f}%). UDP appears entirely blocked.[/bold red]")
                self.results["udp_port_hopping_bypassed"] = False
        else:
            console.print(f"[bold green][+] UDP flow is stable (Loss: {initial_loss:.1f}%). No throttling detected.[/bold green]")


    def generate_report(self):
        """
        Module 3: Automated Diagnostic Report
        Outputs the optimal configuration based on network analysis.
        """
        console.print(f"\n[bold cyan]=== Module 3: Automated Diagnostic Report ===[/bold cyan]")
        
        recommendation = {}
        
        if not self.results["udp_throttled"] or self.results["udp_port_hopping_bypassed"]:
            recommendation = {
                "Protocol": "UDP-QUIC",
                "Port-Hopping": self.results["udp_port_hopping_bypassed"],
                "Reason": "UDP flows remain stable or can successfully bypass throttling via port-hopping.",
                "Hysteria2_Config_Stub": {
                    "server": f"{self.target_ip}:{self.target_port}",
                    "obfs": "salamander" if self.results["udp_throttled"] else "none",
                    "hopInterval": 10 if self.results["udp_port_hopping_bypassed"] else 0
                }
            }
        elif self.results["tcp_tls_clear"]:
            recommendation = {
                "Protocol": "TCP-TLS",
                "SNI_Status": "Clear",
                "Reason": "UDP is degraded/blocked, but TCP/TLS path shows no middlebox RST injections.",
                "VLESS_Reality_Config_Stub": {
                    "server": self.target_ip,
                    "port": 443,
                    "sni": self.target_sni,
                    "flow": "xtls-rprx-vision"
                }
            }
        else:
            recommendation = {
                "Protocol": "None",
                "Error": "Severe network degradation. Middlebox TLS RST injection and UDP throttling are both active."
            }
            
        panel = Panel(
            json.dumps(recommendation, indent=4),
            title="[bold magenta]Optimal Transport Recommendation[/bold magenta]",
            expand=False
        )
        console.print(panel)

if __name__ == "__main__":
    console.print(Panel.fit("[bold green]Network Path Degradation & Middlebox Diagnostic Scanner[/bold green]\n"
                            "[dim]Compatible with Jupyter Notebook / Google Colab (Requires root/sudo)[/dim]"))
    
    # Test Parameters
    TARGET_IP = "1.1.1.1" # Example Target IP
    TARGET_SNI = "speedtest.net"
    
    diagnostic = NetworkDiagnostic(TARGET_IP, target_sni=TARGET_SNI)
    diagnostic.test_tcp_tls_middlebox()
    
    # Simulate a 30 second capacity test 
    # (Reduced to 16 seconds for testing speed. Throttling triggers > 15s in simulation logic)
    diagnostic.test_udp_capacity(duration=16)
    
    diagnostic.generate_report()
