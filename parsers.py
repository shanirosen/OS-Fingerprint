from statistics import mean, stdev
from math import log2
from config import REQUIRED_RESPONSES
from utils import find_gcd
from scapy.layers.inet import IP, TCP, UDP, UDPerror, IPerror, ICMP
from scapy.packet import NoPayload
from scapy.compat import raw
from utils import parse_diffs, all_equal, avg_inc_per_sec

def ts_parser(packets):
    timestamps = []
    ans_counter = 0
    for pkt in packets:
        for snd, rcv in pkt:
            if rcv is not None:
                ans_counter += 1
                ts = [item for item in rcv[TCP].options if item[0] == 'Timestamp']
                if len(ts) > 0:
                    timestamps.append(ts[0])

    avg_inc = avg_inc_per_sec(timestamps)

    if len(timestamps) < ans_counter and ans_counter > 0:
        return {"TS": "U"}
    elif any([item for item in timestamps if item[1][0] == 0]):
        return {"TS": 0}
    elif 0 <= avg_inc <= 5.66:
        return {"TS": 1}
    elif 70 <= avg_inc <= 150:
        return {"TS": 7}
    elif 150 <= avg_inc <= 350:
        return {"TS": 8}
    else:
        return {"TS": round(log2(avg_inc))}


def get_tg(i_ttl):
    if (i_ttl <= 32):
        tg = 32
    elif (i_ttl > 32 and i_ttl <= 64):
        tg = 64
    elif (i_ttl > 64 and i_ttl <= 128):
        tg = 128
    else:
        tg = 255
    return tg


def ie_parser(packets):
    res = {"IE": {}}
    answers = []
    probes = []
    for pkt in packets:
        for snd, rcv in pkt:
            if rcv is not None:
                answers.append(rcv)
            probes.append(snd)
    if (len(answers) < 2):
        res["IE"]["R"] = "N"
    else:
        if (not answers[0].flags.DF and not answers[1].flags.DF):
            res["IE"]["DFI"] = "N"
        elif (answers[0].flags.DF == probes[0].flags.DF and answers[1].flags.DF == probes[1].flags.DF):
            res["IE"]["DFI"] = "S"
        elif (answers[0].flags.DF and answers[1].flags.DF):
            res["IE"]["DFI"] = "Y"
        else:
            res["IE"]["DFI"] = "O"

        res["IE"]["T"] = answers[0].ttl

        tg = get_tg(answers[0].ttl)
        res["IE"]["TG"] = tg

        if (answers[0][ICMP].code == 0 and answers[1][ICMP].code == 0):
            res["IE"]["CD"] = "Z"
        elif (answers[0][ICMP].code == probes[0][ICMP].code and answers[1][ICMP].code == probes[1][ICMP].code):
            res["IE"]["CD"] = "S"
        elif (answers[0][ICMP].code == answers[1][ICMP].code):
            res["IE"]["CD"] = answers[0][ICMP].code
        else:
            res["IE"]["CD"] = "O"
    return res


def sp_parser(seq_list, seq_rates, gcd):
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


def ti_ci_ii_parser(packets, test):
    ids = []
    res = {test: ""}
    num = REQUIRED_RESPONSES[test]
    for pkt in packets:
        for snd, rcv in pkt:
            if rcv is not None:
                ids.append(int(rcv[IP].id))

    if (len(ids) >= num):
        diffs = parse_diffs(ids)

        if (all_equal(ids) and all(item != 0 for item in ids)):
            res[test] = f'{ids[0]:x}'

        elif all(item == 0 for item in ids):
            res[test] = "Z"

        elif any(item >= 20000 for item in diffs) and test != "II":
            res[test] = "RD"

        elif any(item > 1000 and item % 256 != 0 for item in diffs):
            res[test] = "RI"

        elif all(item % 256 == 0 and item <= 5120 for item in diffs):
            res[test] = "BI"

        elif all(item < 10 for item in diffs):
            res[test] = "I"
        else:
            res = {}
    else:
        res = {}

    return res


def ss_parser(icmp_pkts, tcp_pkts):
    tcp_ip_ids = []
    icmp_ip_ids = []
    i = 0
    for pkt in tcp_pkts:
        for snd, rcv in pkt:
            i += 1
            if rcv is not None:
                tcp_ip_ids.append((rcv[IP].id, i))

    for pkt in icmp_pkts:
        for snd, rcv in pkt:
            if rcv is not None:
                icmp_ip_ids.append(rcv[IP].id)

    avg = (tcp_ip_ids[0][0]-tcp_ip_ids[-1][0]) / \
        (tcp_ip_ids[0][1]-tcp_ip_ids[-1][1])

    if (len(icmp_ip_ids) == 0):
        return {}

    elif (icmp_ip_ids[0] < tcp_ip_ids[-1][0] + 3 * avg):
        return {"SS": "S"}
    else:
        return {"SS": "O"}


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

    sp = sp_parser(seq_list, seq_rates, gcd)

    res["SEQ"] = {
        "SP": sp,
        "GCD": gcd,
        "ISR": isr,
    }

    return res


def u1_parser(snd, rcv):
    res = {}
    if rcv is None:
        res["R"] = "N"
    else:
        res["R"] = "Y"
        res["DF"] = "Y" if rcv.flags.DF else "N"
        res["TOS"] = rcv.tos
        res["T"] = rcv.ttl
        res["W"] = rcv.window
        res["IPL"] = rcv.len
        res["RIPL"] = rcv.payload.payload.len
        res["RID"] = "G" if rcv[IPerror].id == 4162 else rcv[IPerror].id
        res["RIPCK"] = "G" if snd.chksum == rcv[IPerror].chksum else (
            "Z" if rcv[IPerror].chksum == 0 else "I"
        )
        # res["RUCK"] = "E" if snd.payload.chksum == rcv[UDPerror].chksum else (
        #     "0" if rcv[UDPerror].chksum == 0 else "F"
        # )
        res["ULEN"] = rcv[UDPerror].len
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
                    res[key]["W"] = rcv.window
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
                res["WIN"][f"W{index}"] = rcv.window
            else:
                continue

    for key in res:
        if not res[key]:
            res.pop(key, None)

    return res
