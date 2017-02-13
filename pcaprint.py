#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from utils import *
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fingerprint and classify packets of given PCAP.')
    parser.add_argument('-p', '--display', action='store_true', default=False,
                help='Print each fingerprinted packet (p0f display style).')
    parser.add_argument('-o', '--output', default=None,
                help='Output classified hosts in XML form.')
    parser.add_argument('-c', '--capture', default=None, required=True,
                help='PCAP file to process.')
    args = parser.parse_args()

    pcap = rdpcap(args.capture)
    if args.output is not None:
        exportXML(pcap, args.output)
    if args.display is not False:
        for cap in pcap:
            TCPshow(cap)
