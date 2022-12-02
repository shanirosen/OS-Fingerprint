import logging
import socket
import validators
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #disable scqpy warnings
from core.utils.fp_utils import get_final_fp_guess, port_scanner, matching_algorithm, create_fp_for_host, resolve_host
from core.utils.nmapdb_utils import create_nmap_os_db
from core.utils.general_utils import prettify_ports
from config.config import PORT_RANGE, BANNER
from scapy.config import conf
from scapy.arch import WINDOWS
from more_itertools import take
from termcolor import colored
from halo import Halo

class OS_Fingerprint_Finder:
    def __init__(self, host, timeout, is_fast, show_ports, top_results):
        self.host = host
        self.timeout = timeout if timeout else 2
        self.is_fast = is_fast
        self.show_ports = show_ports
        self.top_results = top_results

    def find_os_fp(self):
        print(BANNER)
        conf.verb = 0

        nmap_os_db = create_nmap_os_db()

        if validators.domain(self.host):
            self.host = resolve_host(self.host)

        else:
            socket.inet_aton(self.host)
            
        ports_results, open_ports = port_scanner(self.host, PORT_RANGE, self.is_fast)

        if self.show_ports:
            print(prettify_ports(ports_results))

        if len(open_ports) == 0:
            print(colored(
                "WARNING: No open ports found, cannot guess os fingerprint. Aborting!", "yellow"))
            return

        possible_fp_results = []
        spinner = Halo(text='Finding a Fingerprint...', spinner='dots')
        
        for oport in open_ports:
            spinner.start()
            final_res = create_fp_for_host(self.host, oport, 1, self.timeout)
            fp_matches = matching_algorithm(nmap_os_db, final_res)
            possible_fp_results.append(take(self.top_results, fp_matches.items()))
        spinner.stop()
        
        final_os_guess = get_final_fp_guess(possible_fp_results, self.top_results)
        print(final_os_guess)

