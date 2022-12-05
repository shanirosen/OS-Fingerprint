from prettytable import PrettyTable
from functools import reduce
from math import gcd
from config.config import LIMIT
from core.utils.fp_utils import resolve_host
import validators
import socket

def find_gcd(lst: list) -> int:
    """
    Calculates greatest common divisor from a list of integers.

    Args:
        lst (list): list of numbers

    Returns:
        int: great common divisor
    """
    x = reduce(gcd, lst)
    return x


def parse_diffs(param_list: list):
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


def avg_inc_per_sec(timestamps: list):
    diffs = []
    for i in range(len(timestamps) - 1):
        first_pkt = timestamps[i]
        scnd_pkt = timestamps[i+1]
        diffs.append((scnd_pkt[1]-first_pkt[1]) /
                     0.1 * (scnd_pkt[0] - first_pkt[0]))

    return sum(diffs)/len(diffs)


def all_equal(iterator: iter):
    return len(set(iterator)) <= 1


def prettify_ports(ports_results):
    ports_table = PrettyTable()
    ports_table.field_names = ["Port", "Status", "Service"]
    ports_table.add_rows(ports_results)
    return ports_table

def validate_host(host: str):
    if validators.domain(host):
            host = resolve_host(host)
    else:
        socket.inet_aton(host)
    return host