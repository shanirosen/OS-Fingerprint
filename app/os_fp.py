from core.utils.fp_utils import get_final_fp_guess, port_scanner, matching_algorithm, create_fp_for_host
from core.utils.nmapdb_utils import create_nmap_os_db
from core.utils.general_utils import prettify_ports
from config.config import PORT_RANGE, BANNER
from scapy.config import conf
from scapy.arch import WINDOWS
from more_itertools import take
from termcolor import colored
from halo import Halo


def os_fp(host, timeout, isFast, show_ports, top_results):
    print(BANNER)
    conf.verb = 0

    nmap_os_db = create_nmap_os_db()

    ports_results, open_ports = port_scanner(host, PORT_RANGE, isFast)

    if show_ports:
        print(prettify_ports(ports_results))

    if len(open_ports) == 0:
        print(colored(
            "WARNING: No open ports found, cannot guess os fingerprint. Aborting!", "yellow"))
        return

    possible_fp_results = []
    spinner = Halo(text='Finding a Fingerprint...', spinner='dots')
    for oport in open_ports:
        spinner.start()
        final_res = create_fp_for_host(host, oport, 1, timeout)
        # print(final_res)
        fp_matches = matching_algorithm(nmap_os_db, final_res)
        possible_fp_results.append(take(top_results, fp_matches.items()))

    spinner.stop()
    final_os_guess = get_final_fp_guess(possible_fp_results, top_results)
    print(final_os_guess)

