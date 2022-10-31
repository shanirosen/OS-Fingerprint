import re
import itertools
import pandas as pd
from math import log2
from functools import reduce
from math import gcd
from tqdm import tqdm
from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr, sr1
import random


def port_scanner(host, port_range):
    print("\nScanning Ports...\n")
    results = []

    for dst_port in tqdm(port_range, colour="yellow"):
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1,
            verbose=0,
        )

        if resp is None:
            results.append([dst_port, "Filtered", port_range[dst_port]])

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                send_rst = sr1(
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


def find_gcd(list):
    x = reduce(gcd, list)
    return x


def list_to_dict(lst):
    dct = {}
    for item in lst:
        splitted = item.split("=")
        if len(splitted) > 1:
            dct[splitted[0]] = splitted[1]
        else:
            dct[splitted[0]] = ""
    return dct


def parse_nmap_os_db(path):
    parsed_os_db = {}

    with open(path) as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]

    parsed_list = [list(g) for k, g in itertools.groupby(
        lines, lambda x:x in '') if not k]

    for item in parsed_list:
        key = ""

        for value in item:
            if "Fingerprint" in value:
                key = value
                parsed_os_db[value] = {}
                break
            else:
                continue

        for value in item:
            param = re.match("(.*?)\(", value)
            try:
                param = param.group()
            except:
                continue
            mark = value.find("(")
            data = value[mark+1:-1]
            data_list = data.split("%")
            parsed_os_db[key][param[:-1]] = list_to_dict(data_list)

    return parsed_os_db


def parse_fingerprints(fp_results):
    df = pd.DataFrame(fp_results)

    df[0] = df[0].apply(lambda x: " ".join(x.split(" ")[1:]))

    df.rename({0: "OS", 1: "Probability"}, axis=1, inplace=True)

    grouped_df = df.groupby("OS", as_index=False).mean()
    grouped_df.sort_values("Probability", ascending=False, inplace=True)
    grouped_df["Probability"] = grouped_df["Probability"].apply(
        lambda x: str(round((x*100), 2)) + "%")
    top10 = grouped_df.reset_index(drop=True).head(10)

    return top10


def packet_sender(tests, interval=0.1):
    answers = []
    print("\nSending Packets...\n")
    for packet in tqdm(tests, colour="green"):
        ans, unans = sr(packet, timeout=2, inter=interval)
        ans.extend((x, None) for x in unans)
        answers.append(ans)
    return answers
