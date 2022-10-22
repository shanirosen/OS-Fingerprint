import re
import itertools
import pandas as pd


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
