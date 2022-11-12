import re
import itertools
import pandas as pd
from math import log2
from functools import reduce
from math import gcd
from scapy.arch import WINDOWS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr, sr1
import random
import json
from config import OS_DB_PATH, LIMIT, MATCH_POINTS
from halo import Halo
import operator
from prettytable import PrettyTable


def parse_diffs(param_list):
    diffs = []
    for i in range(len(param_list) - 1):
        first = param_list[i]
        second = param_list[i + 1]
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


def avg_inc_per_sec(timestamps):
    diffs = []
    for i in range(len(timestamps) - 1):
        first_pkt = timestamps[i]
        scnd_pkt = timestamps[i+1]
        diffs.append((scnd_pkt[1]-first_pkt[1]) / 0.1 * (scnd_pkt[0] - first_pkt[0]))
        
    return sum(diffs)/len(diffs)


def all_equal(iterator):
    return len(set(iterator)) <= 1


def port_scanner(host, port_range):
    spinner = Halo(text='Scanning Ports...', spinner='dots')
    results = []
    open_ports = []
    for dst_port in (port_range):
        spinner.start()
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1,
            verbose=0,
        )

        if resp is None:
            results.append([dst_port, "Filtered", port_range[dst_port]])

        elif (resp.haslayer(TCP)):
            if (resp.getlayer(TCP).flags == 0x12):
                sr1(
                    IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags='R'),
                    timeout=1,
                    verbose=0,
                )
                results.append([dst_port, "Open", port_range[dst_port]])
                open_ports.append(dst_port)

            elif (resp.getlayer(TCP).flags == 0x14):
                results.append(
                    [dst_port, "Closed", port_range[dst_port]])

        elif (resp.haslayer(ICMP)):
            if (
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                results.append(
                    [dst_port, "Filtered", port_range[dst_port]])

    spinner.stop()
    return results, open_ports


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


def parse_hex(fingerprints):
    for fp in fingerprints:
        for cat in fingerprints[fp]:
            for test in fingerprints[fp][cat]:
                result = []
                if test in ["TI", "CI", "II", "SS"]:
                    splitted = fingerprints[fp][cat][test].split('|')
                    fingerprints[fp][cat][test] = splitted
                    continue
                if test in ['SP', 'GCD', 'ISR', "W", "W1", "W2", "W3", "W4", "W5", "W6", "TG", "T", "TS", "UN", "RIPL", "IPL"]:
                    if test == "TS" and fingerprints[fp][cat][test] == "U":
                        fingerprints[fp][cat][test] == ["U"]
                        continue
                    if test == "RIPL" and fingerprints[fp][cat][test] == "G":
                        fingerprints[fp][cat][test] == ["G"]
                        continue
                    splitted = fingerprints[fp][cat][test].split('|')
                    for item in splitted:
                        if '>' in item:
                            number = int(item[1:], base=16)
                            item = [('gt', number)]
                            result.append(item)
                            continue
                        elif '<' in item:
                            number = int(item[1:], base=16)
                            item = [('lt', number)]
                            result.append(item)
                            continue
                        ranged = item.split('-')
                        if len(ranged) > 1:
                            first = int(ranged[0], base=16)
                            last = int(ranged[1], base=16)
                            range_list = list(range(first, last+1))
                            result.append(range_list)
                        else:
                            result.append([int(ranged[0], base=16)])
                    flat_list = [
                        item for sublist in result for item in sublist]
                    fingerprints[fp][cat][test] = flat_list
    return fingerprints


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
            param = re.match("(.*?)\(.*\=.*\)$", value)
            try:
                value = param.group()
                category = param.group(1)
            except:
                continue
            mark = value.find("(")
            data = value[mark+1:-1]
            data_list = data.split("%")
            parsed_os_db[key][category] = list_to_dict(data_list)

    fully_parsed = parse_hex(parsed_os_db)
    with open(OS_DB_PATH, 'w') as f:
        f.write(json.dumps(fully_parsed))

    return parsed_os_db


def get_final_fp_guess(fp_results):
    fp_results = [item for sublist in fp_results for item in sublist]

    df = pd.DataFrame(fp_results)

    df[0] = df[0].apply(lambda x: " ".join(x.split(" ")[1:]))

    df.rename({0: "OS", 1: "Probability"}, axis=1, inplace=True)

    grouped_df = df.groupby("OS", as_index=False).mean()
    grouped_df.sort_values("Probability", ascending=False, inplace=True)
    grouped_df["Probability"] = grouped_df["Probability"].apply(
        lambda x: str(round((x*100), 2)) + "%")
    top10 = grouped_df.reset_index(drop=True).head(50)

    return top10


def packet_sender(tests, interval=0.1):
    answers = []
    for packet in tests:
        ans, unans = sr(packet, timeout=5, inter=interval)
        ans.extend((x, None) for x in unans)
        answers.append(ans)
    return answers


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
        results[fp] = match_points / possible_points
    
    sorted_res = dict(
        sorted(results.items(), key=operator.itemgetter(1), reverse=True))
    return sorted_res

def prettify_ports(ports_results):
    ports_table = PrettyTable()
    ports_table.field_names = ["Port", "Status", "Service"]
    ports_table.add_rows(ports_results)
    return ports_table