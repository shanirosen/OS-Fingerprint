from utils import parse_nmap_os_db, get_final_fp_guess, packet_sender, port_scanner, matching_algorithm, prettify_ports
from config import PATH, PORT_RANGE, BANNER, OS_DB_PATH
from scapy.config import conf
from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from more_itertools import take
from prettytable import PrettyTable
from termcolor import colored
from parsers import seq_parser, t1_t7_u1_parser, tcp_ops_win_parser, ti_ci_ii_parser, ie_parser, ss_parser, ts_parser, ecn_parser, cc_parser
import os
import random
import json
from halo import Halo


def t1_t7_u1_config(host, oport, cport):
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

    T1 = IP(dst=host) / TCP(sport=src_port + 1, dport=oport, options=[("WScale", 10), ("NOP", None), ("SAckOK", ""),
                                                              ("MSS", 1460), ("Timestamp", (4294967295, 0))], window=1)
    T2 = IP(dst=host, flags="DF") / TCP(seq=1, sport=src_port + 2,
                                        dport=oport, options=tcpopt, flags="", window=128)
    
    T3 = IP(dst=host) / TCP(seq=1, sport=src_port + 3,
                            dport=oport, options=tcpopt, flags="SFUP", window=256)
    
    T4 = IP(dst=host, flags="DF") / TCP(seq=1, sport=src_port + 4,
                                        dport=oport, options=tcpopt, flags="A", window=512)
    
    T5 = IP(dst=host) / TCP(seq=1, sport=src_port + 5,
                            dport=cport, options=tcpopt, flags="S", window=31337)
    
    T6 = IP(dst=host, flags="DF") / TCP(seq=1, sport=src_port + 6,
                                        dport=cport, options=tcpopt, flags="A", window=32768)
    
    T7 = IP(dst=host) / TCP(seq=1, sport=src_port + 7,
                            dport=cport, options=tcpopt2, flags="FPU", window=65535)

    U1 = IP(dst=host, id=1042) / UDP(sport=src_port + 8, dport=cport) / (300 * "C")

    return [T1, T2, T3, T4, T5, T6, T7, U1]


def ecn_config(host, oport):
    src_port = random.randint(1025, 65534)
    ECN = IP(dst=host) / TCP(sport = src_port, dport=oport, flags="SEC", reserved=1, urgptr=63477, options=[("WScale", 10), ("NOP", None),("MSS", 1460), ("SAckOK", ""), ("NOP", None), ("NOP", None)], window=3)
    return [ECN]


def t5_t7_config(host, cport):
    tcpopt = [("WScale", 10),
              ("NOP", None),
              ("MSS", 265),
              ("Timestamp", (4294967295, 0))]
    T5 = IP(dst=host) / TCP(seq=1, sport=4005,
                            dport=cport, options=tcpopt, flags="S", window=31337)
    T6 = IP(dst=host, flags="DF") / TCP(seq=1, sport=4006,
                                        dport=cport, options=tcpopt, flags="A", window=32768)
    T7 = IP(dst=host) / TCP(seq=1, sport=4007,
                            dport=cport, options=tcpopt, flags="FPU", window=65535)
    return [T5, T6, T7]


def seq_config(host, oport):
    # SEQ probes #1-#6
    
    sport_prefix = random.randint(10, 99)
    src_port = sport_prefix * 100
    
    packet1 = IP(dst=host) / TCP(sport=src_port + 1, dport=oport, options=[("WScale", 10), ("NOP", None), ("SAckOK", ""), ("MSS", 1460), ("Timestamp", (4294967295, 0))], window=1)
    
    packet2 = IP(dst=host) / TCP(sport=src_port + 2,  dport=oport, options=[("MSS", 1400), ("WScale", 0), ("SAckOK", ""), ("Timestamp", (4294967295, 0)), ("EOL", None)], window=63)

    packet3 = IP(dst=host) / TCP(sport=src_port + 3, dport=oport, options=[("Timestamp", (4294967295, 0)), ("NOP", None), ("NOP", None), ("WScale", 5), ("NOP", None), ("MSS", 640)], window=4)

    packet4 = IP(dst=host) / TCP(sport=src_port + 4, dport=oport, options=[("SAckOK", ""), ("Timestamp", (4294967295, 0)), ("WScale", 10), ("EOL", None)], window=4)

    packet5 = IP(dst=host) / TCP(sport=src_port + 5, dport=oport, options=[("WScale", 10), ("MSS", 536), ("SAckOK", ""), ("Timestamp", (4294967295, 0)), ("EOL", None)], window=16)

    packet6 = IP(dst=host) / TCP(sport=src_port + 6, dport=oport, options=[("MSS", 265), ("SAckOK", ""), ("Timestamp", (4294967295, 0))], window=512)

    return [packet1, packet2, packet3, packet4, packet5, packet6]


def icmp_config(host):
    ip_id = random.randint(0, 65534)
    icmp_id = random.randint(0, 65534)
    packet1 = IP(dst=host, id=ip_id, flags="DF", tos=0) / ICMP(seq=295, id=icmp_id, code=9) / (120 * '\x00')
    packet2 = IP(dst=host, id=ip_id + 1, flags="DF", tos=4) / ICMP(seq=296, id=icmp_id + 1, code=0) / (150 * '\x00')

    return [packet1, packet2]


def parse_all_packets(tcp_ans, seq_ans, icmp_ans, tcp_cport_ans, ecn_ans):
    t1_t7_u1 = t1_t7_u1_parser(tcp_ans)
    ops_win = tcp_ops_win_parser(seq_ans)
    seq = seq_parser(seq_ans)
    ecn = ecn_parser(ecn_ans)


    ti = ti_ci_ii_parser(seq_ans, "TI")
    ts = ts_parser(seq_ans)
    ci = ti_ci_ii_parser(tcp_cport_ans, "CI")
    ii = ti_ci_ii_parser(icmp_ans, "II")
    ie = ie_parser(icmp_ans)


    if (len(ii.keys()) > 0 and (ii["II"] == "RI" or ii["II"] == "BI" or ii["II"] == "I") and ti["TI"] == ii["II"]):
        ss = ss_parser(icmp_ans, seq_ans)
    else:
        ss = {}

    seq["SEQ"] = {**seq["SEQ"], **ti, **ii, **ci, **ss, **ts}

    return {**seq, **t1_t7_u1, **ops_win, **ie, **ecn}


def send_and_parse_packets(host, oport, cport):

    seq_probes = seq_config(host, oport)
    icmp_probes = icmp_config(host)
    tcp_probes = t1_t7_u1_config(host, oport, cport)
    tcp_cport_probes = t5_t7_config(host, cport)
    ecn_probes = ecn_config(host, oport)

    seq_ans = packet_sender(seq_probes)
    icmp_ans = packet_sender(icmp_probes)
    tcp_ans = packet_sender(tcp_probes)
    tcp_cport_ans = packet_sender(tcp_cport_probes)
    ecn_ans = packet_sender(ecn_probes)
    
    final_res = parse_all_packets(tcp_ans, seq_ans, icmp_ans, tcp_cport_ans, ecn_ans)
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
    
    possible_fp_results = []
    spinner = Halo(text='Finding a Fingerprint...', spinner='dots')
    for oport in open_ports:
        spinner.start()
        final_res = send_and_parse_packets(host, oport, cport)
        print(final_res)
        fp_matches = matching_algorithm(nmap_os_db, final_res)
        possible_fp_results.append(take(50, fp_matches.items()))

    spinner.stop()
    final_os_guess = get_final_fp_guess(possible_fp_results)
    print(final_os_guess)


os_fp("45.33.32.156")

# def test():
#     probes = ecn_config("45.33.32.156", 22)
#     packet_sender(probes)

# test()