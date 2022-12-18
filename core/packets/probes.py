from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, UDP, ICMP
import random

class Probes:
    def __init__(self, host: str, oport: int, cport: int):
        """A class representing all the needed probes to send to the host, according to nmap's tests.
        After each probe is defined, the probes are sent to the host by the probe sender.
        The full description of the probes can be found on nmap's website.
        Args:
            host (str): the relevant host
            oport (int): open port of the host
            cport (int): closed port of the host
        """
        self.host = host
        self.cport = cport
        self.oport = oport
        
    
    def t1_t7_u1_probes(self):
        # TCP T1-T7
        tcpopt = [("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("SAckOK", ""),
                ("Timestamp", (4294967295, 0))]

        tcpopt2 = [("WScale", 14),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (4294967295, 0))]

        sport_prefix = random.randint(10, 99)
        src_port = sport_prefix * 100

        T1 = IP(dst=self.host) / TCP(sport=src_port + 1, dport=self.oport, options=[("WScale", 10), ("NOP", None), ("SAckOK", ""),
                                                                        ("MSS", 1460), ("Timestamp", (4294967295, 0))], window=1)
        T2 = IP(dst=self.host, flags="DF") / TCP(seq=1, sport=src_port + 2,
                                            dport=self.oport, options=tcpopt, flags="", window=128)

        T3 = IP(dst=self.host) / TCP(seq=1, sport=src_port + 3,
                                dport=self.oport, options=tcpopt, flags="SFUP", window=256)

        T4 = IP(dst=self.host, flags="DF") / TCP(seq=1, sport=src_port + 4,
                                            dport=self.oport, options=tcpopt, flags="A", window=512)

        T5 = IP(dst=self.host) / TCP(seq=1, sport=src_port + 5,
                                dport=self.cport, options=tcpopt, flags="S", window=31337)

        T6 = IP(dst=self.host, flags="DF") / TCP(seq=1, sport=src_port + 6,
                                            dport=self.cport, options=tcpopt, flags="A", window=32768)

        T7 = IP(dst=self.host) / TCP(seq=1, sport=src_port + 7,
                                dport=self.cport, options=tcpopt2, flags="FPU", window=65535)

        U1 = IP(dst=self.host, id=1042) / \
            UDP(sport=src_port + 8, dport=self.cport) / (300 * "C")

        return [T1, T2, T3, T4, T5, T6, T7, U1]


    def ecn_probes(self):
        src_port = random.randint(1025, 65534)
        ECN = IP(dst=self.host) / TCP(sport=src_port, dport=self.oport, flags="SEC", reserved=1, urgptr=63477, options=[
            ("WScale", 10), ("NOP", None), ("MSS", 1460), ("SAckOK", ""), ("NOP", None), ("NOP", None)], window=3)
        return [ECN]


    def t5_t7_probes(self):
        tcpopt = [("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (4294967295, 0))]

        src_port = random.randint(1025, 65534)
        T5 = IP(dst=self.host) / TCP(seq=1, sport=src_port, dport=self.cport,
                                options=tcpopt, flags="S", window=31337)
        T6 = IP(dst=self.host, flags="DF") / TCP(seq=1, sport=src_port,
                                            dport=self.cport, options=tcpopt, flags="A", window=32768)
        T7 = IP(dst=self.host) / TCP(seq=1, sport=src_port, dport=self.cport,
                                options=tcpopt, flags="FPU", window=65535)
        return [T5, T6, T7]


    def seq_probes(self):
        # SEQ probes #1-#6

        sport_prefix = random.randint(10, 99)
        src_port = sport_prefix * 100

        packet1 = IP(dst=self.host) / TCP(sport=src_port + 1, dport=self.oport, options=[
            ("WScale", 10), ("NOP", None), ("SAckOK", ""), ("MSS", 1460), ("Timestamp", (4294967295, 0))], window=1)

        packet2 = IP(dst=self.host) / TCP(sport=src_port + 2,  dport=self.oport, options=[
            ("MSS", 1400), ("WScale", 0), ("SAckOK", ""), ("Timestamp", (4294967295, 0)), ("EOL", None)], window=63)

        packet3 = IP(dst=self.host) / TCP(sport=src_port + 3, dport=self.oport, options=[
            ("Timestamp", (4294967295, 0)), ("NOP", None), ("NOP", None), ("WScale", 5), ("NOP", None), ("MSS", 640)], window=4)

        packet4 = IP(dst=self.host) / TCP(sport=src_port + 4, dport=self.oport, options=[
            ("SAckOK", ""), ("Timestamp", (4294967295, 0)), ("WScale", 10), ("EOL", None)], window=4)

        packet5 = IP(dst=self.host) / TCP(sport=src_port + 5, dport=self.oport, options=[
            ("WScale", 10), ("MSS", 536), ("SAckOK", ""), ("Timestamp", (4294967295, 0)), ("EOL", None)], window=16)

        packet6 = IP(dst=self.host) / TCP(sport=src_port + 6, dport=self.oport, options=[
            ("MSS", 265), ("SAckOK", ""), ("Timestamp", (4294967295, 0))], window=512)

        return [packet1, packet2, packet3, packet4, packet5, packet6]


    def icmp_probes(self):
        ip_id = random.randint(0, 65534)
        icmp_id = random.randint(0, 65534)
        packet1 = IP(dst=self.host, id=ip_id, flags="DF", tos=0) / \
            ICMP(seq=295, id=icmp_id, code=9) / (120 * '\x00')
        packet2 = IP(dst=self.host, id=ip_id + 1, flags="DF", tos=4) / \
            ICMP(seq=296, id=icmp_id + 1, code=0) / (150 * '\x00')

        return [packet1, packet2]
