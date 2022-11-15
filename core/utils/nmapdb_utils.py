import re
import itertools
import json
import os
from config.config import NMAP_OS_DB_PATH, NMAP_OS_DB_TXT


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
                    splitted = fingerprints[fp][cat][test].split('|')
                    for item in splitted:
                        if test == "TS" and item == "U":
                            result.append(item)
                            continue
                        if test == "RIPL" and item == "G":
                            result.append(item)
                            continue
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
    dupes_counter = {}
    with open(path) as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]

    parsed_list = [list(g) for k, g in itertools.groupby(
        lines, lambda x:x in '') if not k]

    for fp in parsed_list:
        for title in fp:
            if "Fingerprint" in title:
                if title in dupes_counter.keys():
                    dupes_counter[title] += 1
                else:
                    dupes_counter[title] = 0

                if title in parsed_os_db.keys():
                    key = f'{title} #{dupes_counter[title]}'

                else:
                    key = title

                parsed_os_db[key] = {}
                break
            else:
                continue

        for title in fp:
            param = re.match("(.*?)\(.*\=.*\)$", title)
            try:
                title = param.group()
                category = param.group(1)
            except:
                continue
            mark = title.find("(")
            data = title[mark+1:-1]
            data_list = data.split("%")
            parsed_os_db[key][category] = list_to_dict(data_list)

    fully_parsed = parse_hex(parsed_os_db)
    with open(NMAP_OS_DB_PATH, 'w') as f:
        f.write(json.dumps(fully_parsed))

    return parsed_os_db


def create_nmap_os_db():
    if (not os.path.exists(NMAP_OS_DB_PATH)):
        parse_nmap_os_db(NMAP_OS_DB_TXT)

    db_file = open(NMAP_OS_DB_PATH)
    nmap_os_db = json.load(db_file)
    return nmap_os_db
