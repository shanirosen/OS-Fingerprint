from core.utils.decorators import timer, performance_check, spinner
from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr, sr1
from config.config import MATCH_POINTS
from halo import Halo
from core.packets.probes import Probes
from more_itertools import take
from termcolor import colored
import operator
import random
import pandas as pd
import socket
import os
os.environ['MPLCONFIGDIR'] = os.getcwd() + "/config/"


def resolve_host(host: str):
    try:
        data = socket.gethostbyname(host)
        return data
    except Exception as e:
        raise Exception(colored("Host Not Found!", "yellow"))


def send_probes(host: str, oport: int, cport: int, timeout: int):
    packet_config = Probes(host, oport, cport)

    seq_probes = packet_config.seq_probes()
    icmp_probes = packet_config.icmp_probes()
    tcp_probes = packet_config.t1_t7_u1_probes()
    tcp_cport_probes = packet_config.t5_t7_probes()
    ecn_probes = packet_config.ecn_probes()

    seq_ans = packet_sender(seq_probes, timeout)
    icmp_ans = packet_sender(icmp_probes, timeout)
    tcp_ans = packet_sender(tcp_probes, timeout)
    tcp_cport_ans = packet_sender(tcp_cport_probes, timeout)
    ecn_ans = packet_sender(ecn_probes, timeout)

    return seq_ans, icmp_ans, tcp_ans, tcp_cport_ans, ecn_ans


@spinner('Scanning Ports...')
def port_scanner(host: str, port_range: dict, is_fast: bool):
    results = []
    open_ports = []
    closed_ports = []

    if is_fast:
        top10 = take(10, port_range.items())
        port_range = dict(top10)

    for dst_port in (port_range):
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=2, verbose=0)

        if resp is None:
            results.append([dst_port, "Filtered", port_range[dst_port]])

        elif (resp.haslayer(TCP)):
            if (resp.getlayer(TCP).flags == 0x12):
                results.append([dst_port, "Open", port_range[dst_port]])
                open_ports.append(dst_port)

            elif (resp.getlayer(TCP).flags == 0x14):
                closed_ports.append(dst_port)
                results.append(
                    [dst_port, "Closed", port_range[dst_port]])

        elif (resp.haslayer(ICMP)):
            if (
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                results.append(
                    [dst_port, "Filtered", port_range[dst_port]])

    return results, open_ports, closed_ports


def get_final_fp_guess(fp_results: list, top_results: int):

    fp_results = [item for sublist in fp_results for item in sublist]

    df = pd.DataFrame(fp_results)

    df[0] = df[0].apply(lambda x: " ".join(x.split(" ")[1:]))

    df.rename({0: "OS", 1: "Probability"}, axis=1, inplace=True)

    grouped_df = df.groupby("OS", as_index=False).mean()
    grouped_df.sort_values("Probability", ascending=False, inplace=True)
    grouped_df["Probability"] = grouped_df["Probability"].apply(
        lambda x: str(round(x, 3)) + "%")
    top = grouped_df.reset_index(drop=True).head(top_results)

    return top


def packet_sender(tests: list, timeout: int):
    answers = []
    for packet in tests:
        ans, unans = sr(packet, timeout=timeout, inter=0.1)
        ans.extend((x, None) for x in unans)
        answers.append(ans)
    return answers


def matching_algorithm(nmap_os_db: dict, res: dict):
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
                except Exception as e:
                    continue
        results[fp] = (match_points / possible_points) * 100
    sorted_res = dict(
        sorted(results.items(), key=operator.itemgetter(1), reverse=True))
    return sorted_res
