from core.args_parser import arg_parser
from app.os_fp_finder import OS_Fingerprint_Finder
import os
import emoji

if __name__ == "__main__":
    # 45.33.32.156
    #  2.56.11.14
    # 110.42.175.54
    # 111.229.255.50
    args = arg_parser()
    
    if args.debug: 
        os.environ['DEBUG'] = "True"
       

    else: os.environ['DEBUG'] = "False"
        
    os_fp_finder = OS_Fingerprint_Finder(args.host, args.timeout, args.fast, args.ports, args.res)
    os_fp_finder.find_os_fp()