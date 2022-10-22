from statistics import mean, stdev
from math import log2
from config import LIMIT
from utils import find_gcd
from scapy.layers.inet import IP, TCP, UDP, UDPerror, IPerror
from scapy.packet import NoPayload
from scapy.compat import raw


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


# TODO: Finish TI, II, TS, and SS.
def seq_parser(packets):
    isr = 0
    seq_list = []
    res = {"SEQ": {}}

    for pkt in packets:
        for snd, rcv in pkt:
            if rcv is not None:
                seq_list.append(rcv.seq)

    diffs = parse_diffs(seq_list)
    gcd = find_gcd(diffs)
    seq_rates = list(map(lambda x: int(x / 0.1), diffs))

    if mean(seq_rates) > 1:
        isr = round(8 * log2(mean(seq_rates)))

    sp = parse_sp(seq_list, seq_rates, gcd)

    res["SEQ"] = {
        "SP": f'{sp:x}',
        "GCD": f'{gcd:x}',
        "ISR": f'{isr:x}',
    }

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
