from core.args_parser import arg_parser
from app.os_fp import OS_Fingerprint_Finder

if __name__ == "__main__":
    # 45.33.32.156
    #  2.56.11.14
    # find more examples
    args = arg_parser()
    os_fp_finder = OS_Fingerprint_Finder(args.host, args.timeout, args.fast, args.ports, args.res)
    os_fp_finder.find_os_fp()