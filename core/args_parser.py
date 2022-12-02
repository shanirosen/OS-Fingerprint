import argparse
from config.config import BANNER


def arg_parser():
    parser = argparse.ArgumentParser(
        prog="OS Fingerprint",
        description='This program returns an estimate for a remote host OS.',
        epilog='To start, run sudo python main.py [host]')
    parser.add_argument("host", help="The IP or hotname/domain of the host")
    parser.add_argument(
        "-f", "--fast", help="Get a faster fingerprint by scanning less ports", action='store_true')
    parser.add_argument(
        "-t", "--timeout", help="Define the timeout for recieving an answer for a packet.\nThe default is 2 seconds.", type=int, dest="timeout")
    parser.add_argument(
        "-r", "--results", help="Define the top number of OS fingerprint results to show. \nThe default is 10. ", type=int, dest="res")
    parser.add_argument(
        "-p", "--ports", help="Show port scan results.", action='store_true')

    args = parser.parse_args()
    return args
