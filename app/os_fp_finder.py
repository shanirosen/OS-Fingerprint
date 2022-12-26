import random
import emoji
import os
from halo import Halo
import logging
logging.getLogger("scapy.runtime").setLevel(
    logging.ERROR)  # disable scqpy warnings
from termcolor import colored
from more_itertools import take
from scapy.arch import WINDOWS
from scapy.config import conf
from config.config import PORT_RANGE, BANNER
from core.utils.decorators import exception_filter, timer
from core.utils.general_utils import prettify_ports, validate_host
from core.utils.nmapdb_utils import create_nmap_os_db
from core.utils.fp_utils import get_final_fp_guess, port_scanner, matching_algorithm, send_probes, resolve_host
from core.packets.packet_parsers.parsers import parse_pkt_res_2_fp


class OS_Fingerprint_Finder:
    """
    A class that represents an OS Fingerprint Finder.
    Args:
        host (string): The host, can be an IP address or domain.
        timeout (int): Timeout in ms for the packet sender.
        is_fast (bool): Should the program ran faster i.e. scan only the top 10 ports.
        show_ports (book): Should the program print the port status on the host.
        top_results (int): How many results to show.

    """
    def __init__(self, host: str, timeout: int, is_fast: bool, show_ports: bool, top_results: int):
        self.host = host
        self.timeout = timeout if timeout else 2
        self.is_fast = is_fast
        self.show_ports = show_ports
        self.top_results = top_results if top_results else 10

    @exception_filter
    @timer
    def find_os_fp(self):
        print(BANNER)
        conf.verb = 0

        nmap_os_db = create_nmap_os_db()

        self.host = validate_host(self.host)
        
        if self.is_fast:
            print(emoji.emojize(":rocket:") + " Fast Mode\n")
        
        if os.environ.get('DEBUG') == "True":
            print(emoji.emojize(":magnifying_glass_tilted_left:") + " Debug Mode\n")
            
        ports_results, open_ports, closed_ports = port_scanner(
            self.host, PORT_RANGE, self.is_fast)

        if self.show_ports:
            print(prettify_ports(ports_results))

        if len(open_ports) == 0 or len(closed_ports) == 0:
            print(colored(
                "WARNING: No open or closed ports found, cannot guess os fingerprint. Aborting!", "yellow"))
            return

        cport = random.choice(closed_ports)
        
        if self.is_fast:
            open_ports = [random.choice(open_ports)]

        possible_fp_results = self._get_possible_fp_results(
            cport, open_ports, nmap_os_db)
        
        final_os_guess = get_final_fp_guess(
            possible_fp_results, self.top_results)
        
        print(f"OS Fingerprint Guesses For {self.host}:\n")
        print(final_os_guess)

    @Halo(text='Finding Fingerprint...', spinner='dots')
    def _get_possible_fp_results(self, cport: int, open_ports: list, nmap_os_db: dict) -> list:
        """
        The main function that guesses the fingerprint result, according to nmap's tests.
        Args:
            cport (int): closed port
            open_ports (list): a list of open ports of the host
            nmap_os_db (dict): parsed nmap os db
        Returns:
            list: a list that contains the top n results of the matching fingerprints in the db.
        """
        possible_fp_results = []
        for oport in open_ports:
            seq_ans, icmp_ans, tcp_ans, tcp_cport_ans, ecn_ans = send_probes(
                self.host, oport, cport, self.timeout)
            final_res = parse_pkt_res_2_fp(
                tcp_ans, seq_ans, icmp_ans, tcp_cport_ans, ecn_ans)
            fp_matches = matching_algorithm(nmap_os_db, final_res)
            possible_fp_results.append(
                take(50, fp_matches.items()))

        return possible_fp_results
