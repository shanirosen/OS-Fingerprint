from utils import parse_nmap_os_db, get_final_fp_guess, packet_sender, port_scanner, matching_algorithm, prettify_ports
from config import PATH, PORT_RANGE, BANNER, OS_DB_PATH
from scapy.config import conf
from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from more_itertools import take
from prettytable import PrettyTable
from termcolor import colored
from parsers import seq_parser, t1_t7_u1_parser, tcp_ops_win_parser, ti_ci_ii_parser, ie_parser, ss_parser, ts_parser
import os
import random
import json
from halo import Halo


def t1_t7_u1_config(host, oport, cport):
    # TCP T1-T7
    tcpopt = [("WScale", 10),
              ("NOP", None),
              ("MSS", 256),
              ("Timestamp", (123, 0))]

    T1 = IP(dst=host) / TCP(sport=5001, dport=oport, options=[("WScale", 10), ("NOP", None),
                                                              ("MSS", 1460), ("Timestamp", (123, 0))], window=1)
    T2 = IP(dst=host, flags="DF") / TCP(seq=1, sport=5002,
                                        dport=oport, options=tcpopt, flags="", window=128)
    T3 = IP(dst=host) / TCP(seq=1, sport=5003,
                            dport=oport, options=tcpopt, flags="SFUP", window=256)
    T4 = IP(dst=host, flags="DF") / TCP(seq=1, sport=5004,
                                        dport=oport, options=tcpopt, flags="A", window=1024)
    T5 = IP(dst=host) / TCP(seq=1, sport=5005,
                            dport=cport, options=tcpopt, flags="S", window=31337)
    T6 = IP(dst=host, flags="DF") / TCP(seq=1, sport=5006,
                                        dport=cport, options=tcpopt, flags="A", window=32768)
    T7 = IP(dst=host) / TCP(seq=1, sport=5007,
                            dport=cport, options=tcpopt, flags="FPU", window=65535)

    U1 = IP(dst="127.0.0.1", id=1042) / \
        UDP(sport=5008, dport=cport) / (300 * "C")

    return [T1, T2, T3, T4, T5, T6, T7, U1]


def t5_t7_config(host, cport):
    tcpopt = [("WScale", 10),
              ("NOP", None),
              ("MSS", 256),
              ("Timestamp", (123, 0))]
    T5 = IP(dst=host) / TCP(seq=1, sport=5005,
                            dport=cport, options=tcpopt, flags="S", window=31337)
    T6 = IP(dst=host, flags="DF") / TCP(seq=1, sport=5006,
                                        dport=cport, options=tcpopt, flags="A", window=32768)
    T7 = IP(dst=host) / TCP(seq=1, sport=5007,
                            dport=cport, options=tcpopt, flags="FPU", window=65535)
    return [T5, T6, T7]


def tcp_config(host, oport):
    # SEQ probes #1-#6
    packet1 = IP(dst=host) / TCP(sport=5001, dport=oport, options=[("WScale", 10), ("NOP", None),
                                                                   ("MSS", 1460), ("Timestamp", (123, 0))], window=1)
    packet2 = IP(dst=host) / TCP(sport=5002,  dport=oport, options=[("MSS", 1400), (
        "WScale", 0), ("SAck", ""), ("Timestamp", (123, 0)), ("EOL", None)], window=63)

    packet3 = IP(dst=host) / TCP(sport=5003, dport=oport, options=[("Timestamp", (123, 0)), ("NOP", None), ("NOP", None),
                                                                   ("WScale", 5), ("NOP", None), ("MSS", 640)], window=4)

    packet4 = IP(dst=host) / TCP(sport=5004, dport=oport, options=[("SAck", ""), ("Timestamp", (123, 0)),
                                                                   ("WScale", 10), ("EOL", None)], window=4)

    packet5 = IP(dst=host) / TCP(sport=5005, dport=oport, options=[("WScale", 10), ("MSS", 536),
                                                                   ("SAck", ""), ("Timestamp", (123, 0)), ("EOL", None)], window=6)

    packet6 = IP(dst=host) / TCP(sport=5006, dport=oport,
                                 options=[("MSS", 265), ("SAck", ""), ("Timestamp", (123, 0))], window=512)

    return [packet1, packet2, packet3, packet4, packet5, packet6]


def icmp_config(host):
    ip_id = random.randint(0, 65534)
    icmp_id = random.randint(0, 65534)
    packet1 = IP(dst=host, id=ip_id, flags="DF", tos=0) / \
        ICMP(seq=295, id=icmp_id, code=9) / (120 * "0")
    packet2 = IP(dst=host, id=ip_id + 1, flags="DF", tos=4) / \
        ICMP(seq=295, id=icmp_id + 1, code=0) / (150 * "0")

    return [packet1, packet2]


def parse_all_packets(tcp_ans, seq_ans, icmp_ans, tcp_cport_ans):
    t1_t7_u1 = t1_t7_u1_parser(tcp_ans)
    ops_win = tcp_ops_win_parser(seq_ans)

    ti = ti_ci_ii_parser(seq_ans, "TI")
    ts = ts_parser(seq_ans)
    ci = ti_ci_ii_parser(tcp_cport_ans, "CI")
    ii = ti_ci_ii_parser(icmp_ans, "II")
    ie = ie_parser(icmp_ans)

    if (len(ii.keys()) > 0 and (ii["II"] == "RI" or ii["II"] == "BI" or ii["II"] == "I") and ti["TI"] == ii["II"]):
        ss = ss_parser(icmp_ans, seq_ans)
    else:
        ss = {}

    seq = seq_parser(seq_ans)
    seq["SEQ"] = {**seq["SEQ"], **ti, **ii, **ci, **ss, **ts}

    return {**seq, **t1_t7_u1, **ops_win, **ie}


def send_and_parse_packets(host, oport, cport):
    tcp_probes = t1_t7_u1_config(host, oport, cport)
    tcp_cport_probes = t5_t7_config(host, cport)
    seq_probes = tcp_config(host, oport)
    icmp_probes = icmp_config(host)

    tcp_ans = packet_sender(tcp_probes)
    seq_ans = packet_sender(seq_probes)
    icmp_ans = packet_sender(icmp_probes)
    tcp_cport_ans = packet_sender(tcp_cport_probes)

    final_res = parse_all_packets(tcp_ans, seq_ans, icmp_ans, tcp_cport_ans)
    return final_res

def create_nmap_os_db():
    if (not os.path.exists(OS_DB_PATH)):
        parse_nmap_os_db(PATH)

    db_file = open(OS_DB_PATH)
    nmap_os_db = json.load(db_file)
    return nmap_os_db

def os_fp(host, cport=1):
    print(BANNER)
    conf.verb = 0
    
    nmap_os_db = create_nmap_os_db()
    
    ports_results, open_ports = port_scanner(host, PORT_RANGE)
    
    #print(prettify_ports(ports_results))

    if len(open_ports) == 0:
        print(colored(
            "WARNING: No open ports found, cannot guess os fingerprint. Aborting", "yellow"))
        return

    multiple_fp_results = []
    spinner = Halo(text='Creating Fingerprint...', spinner='dots')
    for oport in open_ports:
        spinner.start()
        final_res = send_and_parse_packets(host, oport, cport)
        fp_matches = matching_algorithm(nmap_os_db, final_res)
        multiple_fp_results.append(take(10, fp_matches.items()))
    
    spinner.stop()
    final_os_guess = get_final_fp_guess(multiple_fp_results)
    print(final_os_guess)


os_fp("45.33.32.156")
