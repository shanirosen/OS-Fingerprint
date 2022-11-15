from core.args_parser import arg_parser
from app.os_fp import os_fp

if __name__ == "__main__":
    # 45.33.32.156
    args = arg_parser()
    os_fp(args.host, args.timeout, args.fast, args.ports, args.res)