from utils import parse_nmap_os_db, parse_fingerprints
from config import MATCH_POINTS, PATH, PORT_RANGE, BANNER, LIMIT
from sys import flags
from scapy.data import KnowledgeBase
from scapy.config import conf
from scapy.arch import WINDOWS
from scapy.error import warning
from scapy.layers.inet import IP, TCP, UDP, ICMP, UDPerror, IPerror, sr1
from scapy.packet import NoPayload
from scapy.sendrecv import sr
from scapy.compat import plain_str, raw
from more_itertools import take
from tqdm import tqdm
import operator
import random
from prettytable import PrettyTable
from termcolor import colored
from math import gcd, log2
from functools import reduce
from statistics import mean, stdev


def find_gcd(list):
    x = reduce(gcd, list)
    return x


def port_scanner(host, port_range):
    print("\nScanning Ports...")
    # Send SYN with random Src Port for each Dst port
    results = []
    for dst_port in port_range:
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1,
            verbose=0,
        )

        if resp is None:
            results.append([dst_port, "Filtered", port_range[dst_port]])

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                # Send a gratuitous RST to close the connection
                send_rst = sr(
                    IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags='R'),
                    timeout=1,
                    verbose=0,
                )
                results.append([dst_port, "Open", port_range[dst_port]])

            elif (resp.getlayer(TCP).flags == 0x14):
                results.append(
                    [dst_port, "Closed", port_range[dst_port]])

        elif(resp.haslayer(ICMP)):
            if(
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                results.append(
                    [dst_port, "Filtered", port_range[dst_port]])

    return results


def packet_sender(tests):
    answers = []
    print("\nSending Packets...\n")
    for packet in tqdm(tests, colour="green"):
        ans, unans = sr(packet, timeout=2)
        ans.extend((x, None) for x in unans)
        answers.append(ans)
    return answers


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


def tcp_ops_win_parser(answers):
    res = {"OPS": {}, "WIN": {}}
    for ans in answers:
        for snd, rcv in ans:
            if rcv is not None:
                index = str(snd.sport - 5000)
                res["OPS"][f"O{index}"] = "".join(
                    x[0][0] for x in rcv[TCP].options)
                res["WIN"][f"W{index}"] = "%X" % rcv.window
            else:
                continue

    for key in res:
        if not res[key]:
            res.pop(key, None)

    return res


#  TODO: finish udp parser
def u1_parser(snd, rcv):
    res = {}
    if rcv is None:
        res["R"] = "N"
    else:
        res["R"] = "Y"
        res["DF"] = "Y" if rcv.flags.DF else "N"
        res["TOS"] = "%X" % rcv.tos
        res["T"] = rcv.ttl
        res["W"] = "%X" % rcv.window
        res["IPL"] = "%X" % rcv.len
        res["RIPL"] = "%X" % rcv.payload.payload.len
        res["RID"] = "G" if rcv[IPerror].id == 4162 else rcv[IPerror].id
        res["RIPCK"] = "G" if snd.chksum == rcv[IPerror].chksum else (
            "Z" if rcv[IPerror].chksum == 0 else "I"
        )
        # res["RUCK"] = "E" if snd.payload.chksum == rcv[UDPerror].chksum else (
        #     "0" if rcv[UDPerror].chksum == 0 else "F"
        # )
        res["ULEN"] = "%X" % rcv[UDPerror].len
        res["DAT"] = "E" if (
            isinstance(rcv[UDPerror].payload, NoPayload) or
            raw(rcv[UDPerror].payload) == raw(snd[UDP].payload)
        ) else "F"
    return res


def t1_t7_u1_parser(answers):
    res = {"U1": {}}
    for ans in answers:
        for snd, rcv in ans:
            if snd.sport == 5008:
                res["U1"] = u1_parser(snd, rcv)
            else:
                key = f"T{snd.sport - 5000}"
                res[key] = {}
                if rcv is not None:
                    res[key]["DF"] = "Y" if rcv.flags.DF else "N"
                    res[key]["W"] = "%X" % rcv.window
                    res[key]["A"] = "S+" if rcv.ack == 2 else "S" if rcv.ack == 1 else "Z" if rcv.ack == 0 else "O"
                    res[key]["F"] = str(rcv[TCP].flags)[::-1]
                    res[key]["O"] = "".join(x[0][0] for x in rcv[TCP].options)
                    res[key]["R"] = "Y"
                    res[key]["T"] = rcv.ttl
                    res[key]["S"] = "A+" if rcv.seq == 2 else "A" if rcv.seq == 1 else "Z" if rcv.seq == 0 else "O"
                else:
                    res[key]["R"] = "N"
    return res


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
                        if res[category][test] == nmap_os_db[fp][category][test]:  # and no operators
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

# TODO: Finish TI, II, TS, and SS.


def parse_diffs(seq_list):
    diffs = []
    for i in range(len(seq_list) - 1):
        first = seq_list[i]
        second = seq_list[i + 1]
        if first >= second:
            first_diff = first - second
            second_diff = LIMIT + second - first
            if first_diff < second_diff:
                diffs.append(first_diff)
            else:
                diffs.append(second_diff)
        else:
            diffs.append(second - first)

    return diffs


def parse_sp(seq_list, seq_rates, gcd):
    sp = None
    if len(seq_list) >= 4:
        if(gcd > 9):
            values = list(map(lambda x: x / gcd, seq_rates))
            result = stdev(values)
        else:
            result = stdev(seq_rates)
        if result <= 1:
            sp = 0
        else:
            sp = round(8 * log2(result))
    return sp


def seq_parser(packets):
    isr = 0
    seq_list = []
    res = {"SEQ": {}}

    for pkt in packets:
        for snd, rcv in pkt:
            if rcv is not None:
                print(rcv.show())
                seq_list.append(rcv.seq)

    diffs = parse_diffs(seq_list)
    gcd = find_gcd(diffs)
    seq_rates = list(map(lambda x: int(x / 0.1), diffs))

    print("seq rates", seq_rates)

    if mean(seq_rates) > 1:
        isr = round(8 * log2(mean(seq_rates)))

    sp = parse_sp(seq_list, seq_rates, gcd)

    res["SEQ"] = {
        "SP": f'{sp:x}',
        "GCD": f'{gcd:x}',
        "ISR": f'{isr:x}',
    }

    return res


def os_fp(host, cport=1):
    print(BANNER)
    conf.verb = 0
    nmap_os_db = parse_nmap_os_db(PATH)
    ports_results = port_scanner(host, PORT_RANGE)
    ports_table = PrettyTable()
    ports_table.field_names = ["Port", "Status", "Service"]
    ports_table.add_rows(ports_results)
    print(ports_table)

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

            final_res = {**t1_t7_u1_res, **tcp_res}
            fp_matches = matching_algorithm(nmap_os_db, final_res)
            fp_results.append(take(10, fp_matches.items()))

        flat = [item for sublist in fp_results for item in sublist]
        parsed = parse_fingerprints(flat)
        print(parsed)


os_fp("45.33.32.156")
