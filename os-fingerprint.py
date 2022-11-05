from utils import parse_nmap_os_db, parse_fingerprints, packet_sender, port_scanner
from config import MATCH_POINTS, PATH, PORT_RANGE, BANNER
from scapy.config import conf
from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, UDP
from more_itertools import take
import operator
from prettytable import PrettyTable
from termcolor import colored
from parsers import seq_parser, t1_t7_u1_parser, tcp_ops_win_parser
from pprint import pprint


def t1_t7_u1_config(host, oport, cport):
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

    tests = [T1, T2, T3, T4, T5, T6, T7, U1]

    return tests


def tcp_config(host, oport):

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

    tests = [packet1, packet2, packet3, packet4, packet5, packet6]
    return tests


def matching_algorithm(nmap_os_db, res):
    results = {}
    for fp in nmap_os_db.keys():
        possible_points = 0
        match_points = 0
        for category in res.keys():
            for test in res[category]:
                try:
                    if nmap_os_db[fp][category][test]:
                        possible_points += MATCH_POINTS[category][test]
                        if type(nmap_os_db[fp][category][test]) == list:
                            if res[category][test] in nmap_os_db[fp][category][test]:
                                match_points += MATCH_POINTS[category][test]
                            else:
                                for item in nmap_os_db[fp][category][test]:
                                    if type(item) == tuple:
                                        if item[0] == 'gt':
                                            if res[category][test] > item[1]:
                                                match_points += MATCH_POINTS[category][test]
                                        else:
                                            if res[category][test] < item[1]:
                                                match_points += MATCH_POINTS[category][test]
                        elif res[category][test] == nmap_os_db[fp][category][test]:
                            match_points += MATCH_POINTS[category][test]
                except:
                    continue
        if match_points > possible_points:
            print(match_points, possible_points)
            print(fp)
        results[fp] = match_points / possible_points
    sorted_res = dict(
        sorted(results.items(), key=operator.itemgetter(1), reverse=True))
    return sorted_res


def os_fp(host, cport=1):
    print(BANNER)
    conf.verb = 0
    nmap_os_db = parse_nmap_os_db(PATH)
    ports_results = port_scanner(host, PORT_RANGE)
    ports_table = PrettyTable()
    ports_table.field_names = ["Port", "Status", "Service"]
    ports_table.add_rows(ports_results)
#    print(ports_table)

    open_ports = []
    for res in ports_results:
        if res[1] == "Open":
            open_ports.append(res[0])

    if len(open_ports) == 0:
        print(colored(
            "WARNING: No open ports found, cannot run os tests. Aborting", "yellow"))
        return

    else:
        fp_results = []
        for oport in open_ports:
            tests1 = t1_t7_u1_config(host, oport, cport)
            tests2 = tcp_config(host, oport)

            answers1 = packet_sender(tests1)
            answers2 = packet_sender(tests2)

            t1_t7_u1_res = t1_t7_u1_parser(answers1)
            tcp_res = tcp_ops_win_parser(answers2)
            seq = seq_parser(answers2)

            final_res = {**t1_t7_u1_res, **tcp_res, **seq}
            pprint(final_res)
            #fp_matches = matching_algorithm(nmap_os_db, final_res)
            ##fp_results.append(take(10, fp_matches.items()))

        # flat = [item for sublist in fp_results for item in sublist]
        # parsed = parse_fingerprints(flat)
        # print(parsed)


os_fp("45.33.32.156")
