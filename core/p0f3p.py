#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import re
from core.layers import *
import sys, os
import Levenshtein
import codecs 

###############################################################################
#          Unofficial p0f3 implementation in Python + plugins for other protos
# Python passive fingerprinter with scapy and based on p0f v3 database
#------------------------------------------------------------------------------
# This script applies the p0f v3 database on packet using different methods 
# to calculate the distance between signatures, but implement some 'push-ack'
# (data) processing methods that can reveal more informations like it should
# be when looking for HTTP headers by example.
#
# Comparing to the initial p0f3 project, this script way slower!!! But could be 
# intersting for Python native implementations to be entirely independant of 
# the p0f3 binary. Moreover, p0f implementation in scapy doesn't support
# the new p0f3 database, which is why this piece of code was developed.
#------------------------------------------------------------------------------
# The module and script supports Python 2 and Python 3 
# (Scapy in Python3 version is available at 
# https://pypi.python.org/pypi/scapy-python3/0.18)
#------------------------------------------------------------------------------
# Author: @FlUxIuS (sebastien.dudek_A|T_synacktiv.com)
# Contributors: needed!
#------------------------------------------------------------------------------
# Tasks to complet =>
# TODO: + complet signature generation for IPv6
#       + complet push-ack signatures --> infinite work
#       + update p0f3 database --> inifite work
#       + implement other distance calculation methods
###############################################################################

dir_ = os.path.dirname(__file__)

default_fp = os.path.abspath(dir_ + "/../data/p0f.fp")


class ClassifiedSignature(object):
    """
        Structure for matched signatures by p0f KB
    """
    top3 = None
    computedsig = None
    signature = None
    label = None
    distance = None
    orig = None

class PacketSignature(object):
    """
        Structure for generated signature
    """
    flag = None
    protocol = None
    signature = None
    packet_type = None
    extra = None

class p0f3p(object):
    """
        p0f3+
        Passive OS and application fingerprinting.
        Two techniques used:
            - p0f3 knowledge base matching
            - payload analysis (extended to other protocols)
    """
    __fpobj = None
    __fppath = None

    def __init__(self, fpfile=None):
        """
            Init p0f python object.
            optional in(1): fpfile path.
        """
        self.__fppath = default_fp
        if fpfile is not None:
            self.__fppath = fpfile

    def parse_p0fconf(self, fpfile=None):
        """
            Parse p0f3 configuration file.
            optional in(1): (string) fpfile path.
        """
        if fpfile is not None:
            self.__fppath = fpfile
        dicts = {}
        p0fcon = open(self.__fppath,"r").read().split("\n")
        cursection = None
        curlabel = None
        cursigs = []
        for i in p0fcon:
            section = re.match(r"\[(\S+)\]", i)
            sig = re.match(r"sig\s+\=\s+(.*)", i)
            label = re.match(r"label\s+\=\s+(.*)", i)
            if section is not None:  
                cursection = section.group(1)
                curlabel = None
                dicts[cursection] = {}
            elif label is not None:
                if curlabel is not None and cursection is not None:
                    dicts[cursection][curlabel] = cursigs
                curlabel = label.group(1)
                cursigs = []
            elif sig is not None:
                cursigs.append(sig.group(1))
        self.__fpobj = dicts
        return dicts

    def getsigs(self):
        """
            Get signature dictionary.
            out: dict signatures.
        """
        return self.__fpobj

    def reaghttp(self, sig_base, sig_pkt):
        """
            Compute HTTP signature base's wildcard with the signature's packet.
                in(1): (string) p0f signature to be compared.
                in(2): (string) pkt's signature to be compared with p0f's one.
                out: adapted signature.
        """
        tsig1 = sig_base.split(":")
        tsig2 = sig_pkt.split(":")
        for x in range(len(tsig1)):
            if x >= len(tsig2):
                break
            tsig1c = tsig1[x].split(",")
            ntsig1c = []
            tsig2c = tsig2[x].split(",")
            for y in range(len(tsig1c)):
                if tsig1c[y] == "":
                    break
                if tsig1c[y][0] == "?":
                    if tsig1c[y][1:] in tsig2c:
                        ntsig1c.append(tsig1c[y][1:])
                else:
                    ntsig1c.append(tsig1c[y])
            tsig1[x] = ",".join(ntsig1c)
            if tsig2[x] == "*":
                tsig2[x] = tsig1[x]
        sig_base = ":".join(tsig1)
        sig_pkt = ":".join(tsig2)
        return (sig_base, sig_pkt)

    def http2sig(self, strload):
        """
            Generates HTTP p0f signature.
                in(1) : (String) strload - pkt load
                out: (Tuple) (visual prints of headers, p0f signature) 
        """
        sig = ""
        server = "*"
        servervalues = {}
        if type(strload).__name__ == "bytes":
            strload = strload.decode("utf-8", "ignore")
        loadtab = strload.split("\r\n")
        valuestopush = ["Accept", 
                        "Accept-Encoding", 
                        "Accept-Ranges", 
                        "Keep-Alive", 
                        "Transfer-Encoding", 
                        "Connection"]
        query = loadtab[0]
        version = None
        name = ""
        try:
            version = re.match(r".*HTTP\/([\d\.]+)", query).group(1)
            sig += version[-1] # keep the last digit of the HTTP version / TODO: look other cases
        except:
            pass
        sig += ":"
        headers = []
        for line in loadtab[1:]:
            if line != "":
                try:
                    header, value = re.match(r"(\S+):\s+(.*)", line).groups()
                    topush = "%s" % header
                    if header in valuestopush: 
                        topush = "%s=[%s]" % (header, value)
                    headers.append(topush)
                    if "Server" in header:
                        # Started to work on a parser, but servers don't have a conventional name, version format :/
                        server = value
                        name, version, os = re.match(r"^([\w\d]+)?/?([\d.]+)?\s?\(?([\d\w\_]+)?", value).groups() # ServerName?/?version ?(distribution)
                        if version is None: # Servername?space?(version)
                            name2, version2 = re.match(r"^([\w\d]+)?\s?\(?([\d\.\w\_]+)?", value).groups()
                            if name2 is not None and version2 is not None:
                                name = name2
                                version = version2
                                os = None
                        # TODO: other corner cases
                        servervalues["application"] = name
                        if name == "":
                            name = re.match(r"^(\w+)", value).groups()
                        servervalues["version"] = version
                        servervalues["os"] = os
                        server = name
                    elif "User-Agent" in header:
                        agents = value.split(" ")
                        selected = agents[-1]
                        for agent in agents:
                            if "Chrome" in agent:
                                selected = agent
                        name, version = re.match(r"^([\w\d]+)?/?([\d.]+)?", selected).groups()
                        servervalues["application"] = name
                        servervalues["version"] = version
                        if "linux" in value.lower(): # os simple match. TODO: Add other OS like the vegetarian one and others...
                             servervalues["os"] = "Linux"
                        elif "windows" in value.lower():
                            servervalues["os"] = "Windows"
                        elif "Mac OS X" in value.lower():
                            servervalues["os"] = "Mac OS X"
                    if "Access" in header or "Allow" in header:
                        servervalues[header.lower()] = value
                except:
                    pass
            else:
                break
        sig += ",".join(headers)
        sig += ":*:%s" % name 
        return (servervalues, sig)

    def pktloadid(self, pkt, pkt_sign):
        """
            Payload identification
            in(1): scapy packet 'pkt'.
            in(2): PacketSignature object
            out: PacketSignature object completed with extra data.
        """
        # HTTP RESPONSES AND REQUESTS
        if b"HTTP/" in pkt.load[:5] or b"GET" in pkt.load[:3]:
            othervalues, sig = self.http2sig(pkt.load)
            pkttype = None
            if pkt.load[:4] == b"HTTP":
                pkttype = "http-response"
            if pkt.load[:3] == b"GET":
                pkttype = "http-request"
            pkt_sign.flag = pkt["TCP"].flags
            pkt_sign.protocol = pkt["IP"].proto
            pkt_sign.signature = sig
            pkt_sign.packet_type = pkttype
            pkt_sign.extra = othervalues
            pkt_sign.extra["apptype"] = 'http'
        # NetBIOS SMB fingerprint processing
        elif b"SMB" in pkt.load[:10]:# and pkt.sport == 139:
            nbios = NetBIOS(pkt.load)
            if nbios.haslayer("SMBHead"):
                try:
                    pkt_sign.extra = {}
                    pkt_sign.extra["application"] = "NetBIOS"
                    pkt_sign.extra["apptype"] = 'smb'
                    pkt_sign.extra["version"] = None
                    pkt_sign.extra["os"] = nbios[SMBHead].SSAXP[SessionSetupAndXResponse].NativeOS.decode('utf-16')
                    pkt_sign.extra["NativeLANManager"] = nbios[SMBHead].SSAXP[SessionSetupAndXResponse].NativeOS.decode('utf-16')
                except Exception:
                    pass
        # SSH fingerprint processing
        elif b"SSH" in pkt.load[:3] and b"\r\n" in pkt.load:
            strload = pkt.load
            pkt_sign.extra = {}
            if type(strload).__name__ == "bytes":
                strload = strload.decode("utf-8", "ignore")
            sshheader = ""
            sshheader = strload.split("\r\n")[0]
            application = None
            version = None
            distribution = None
            try:
                application, version, distribution = re.match(r"^SSH\-[\d\w.]+\-([a-zA-Z0-9]+)?\_?([\w\d.]+)?\s?\(?([\d\w\_]+)?", strload).groups()
                pkt_sign.extra["application"] = application
                pkt_sign.extra["version"] = version
                pkt_sign.extra["os"] = distribution
                pkt_sign.extra["apptype"] = 'ssh'
            except:
                pkt_sign.extra["application"] = sshheader.split("-")[2]
                pkt_sign.extra["version"] = None
                pkt_sign.extra["os"] = None
                pkt_sign.extra["apptype"] = 'ssh'
        # FTP fingerprint processing
        elif b"220" in pkt.load[:3]:
            strload = pkt.load[4:]
            pkt_sign.extra = {}
            if type(strload).__name__ == "bytes":
                strload = strload.decode("utf-8", "ignore")
            match = re.match(r"([\w]+) ([\d\w\.]+)", strload)
            if match is not None:
                pkt_sign.extra["application"] = match.group(1)
                pkt_sign.extra["version"] = match.group(2)
                pkt_sign.extra["apptype"] = 'ftp'
        return pkt_sign

    def pkt2sig(self, pkt):
        """
            Packet2sig - Generate a signature from a packet.
            in(1): (Scapy Packet) pkt.
            out: PacketSignature object.
                Signature are computed respecting the p0f3 specs: http://lcamtuf.coredump.cx/p0f3/README.
        """
        sig = ""
        flag = 0x2 # SYN by default
        proto = None
        pkttype = None # pkttype if ack-push
        pkt_sign = PacketSignature()
        if pkt.haslayer("IP") or pkt.haslayer("IPv6"):
            if pkt.haslayer("IP"):
                proto = pkt["IP"].proto
            else:
                proto = pkt["IPv6"].nh
            sig += str(pkt.version)
            if pkt.haslayer("IP"):
                sig += ":"+str(pkt.ttl)
            # TODO: Olen for IPV6
            sig += ":0"
            if pkt.haslayer("TCP"):
                flag = pkt["TCP"].flags
                if hasattr(pkt["TCP"], "load"): # process the payload to get extra information
                    if len(pkt.load) > 5:
                        # we use a dedicated method to process the signature
                        if b"HTTP/" in pkt.load[:5] or b"GET" in pkt.load[:3]:
                            return self.pktloadid(pkt, pkt_sign)
                        else:
                            pkt_sign = self.pktloadid(pkt, pkt_sign)
                            if pkt.haslayer("IPv6"):
                                return pkt_sign
                optiondict = {}
                for option in pkt["TCP"].options:
                    optiondict[option[0].lower()] = option[1]
                sig += ":"
                if "mss" in optiondict:
                    sig += str(optiondict["mss"])
                sig += ":"
                sig += str(pkt["TCP"].window)
                if "wscale" in optiondict:
                    sig += ","
                    sig += str(optiondict["wscale"])
                diffopt = 0
                if len(pkt["TCP"].options) > 1:
                    temppkt = TCP(bytes(pkt["TCP"]))
                    temppkt.options = []
                    diffopt = len(pkt[TCP])-len(temppkt)
                optionscl = [x.lower() for x,y in pkt[TCP].options]
                noptions = []
                sig += ":"
                """
                    olayout's part
                """
                optionsize = 0
                for ocl in optionscl:
                    if ocl == "sackok":
                        optionsize += 2
                        noptions.append("sok")
                    elif ocl == "timestamp":
                        optionsize += 10
                        noptions.append("ts")
                    elif ocl == "wscale":
                        optionsize += 3
                        noptions.append("ws")
                    elif ocl == "mss":
                        optionsize += 4
                        noptions.append("mss")
                    elif ocl == "eol":
                        optionsize += 1
                        eol_string = "eol+"
                        zdiff = diffopt - optionsize
                        if zdiff > 0:
                            eol_string += str(zdiff)
                        else:
                            eol_string += "0"
                        noptions.append(eol_string)
                    else: # TODO: do more tests and see if a '?n' is required instead
                        optionsize += 1
                        noptions.append(ocl)
                sig += ",".join(noptions)
                sig += ":"
                opt2 = []
                """
                   quirks' part
                """
                if pkt["IP"].version == 4: # TODO: sig for IPv6 packets
                    if pkt["IP"].flags == 0x2:
                        opt2.append("df")
                        if pkt["IP"].id != 0:
                            opt2.append("id+")
                    else:
                        if pkt["IP"].id == 0:
                            opt2.append("id-")
                    if pkt["TCP"].flags & 0b1000000 > 0:
                        opt2.append("ecn")
                    if (pkt["TCP"].flags >> 12) > 0:
                        opt2.append("0+")
                    if pkt["TCP"].seq == 0:
                        opt2.append("seq-")
                    if pkt["TCP"].ack != 0 and (pkt["TCP"].flags & 0b10000 == 0):
                        opt2.append("ack+")
                    elif pkt["TCP"].ack == 0 and (pkt["TCP"].flags & 0b10000 > 0):
                        opt2.append("ack-")
                    if pkt["TCP"].flags & 0b100000 == 0 and hasattr(pkt["TCP"], "urgptr"):
                        if pkt["TCP"].urgptr > 0:
                            opt2.append("uptr+")
                    elif pkt["TCP"].flags & 0b100000 > 0:
                        opt2.append("urgf+")
                    if pkt["TCP"].flags & 0b1000 > 0:
                        opt2.append("pushf+")
                    if "timestamp" in optiondict:
                        if int(optiondict["timestamp"][0]) == 0:
                            opt2.append("ts1-")
                        if int(optiondict["timestamp"][1]) != 0 and pkt["TCP"].flags == 0x2:
                            opt2.append("ts2+")
                    hexlitcp = int(codecs.encode(bytes(pkt[TCP]), "hex"), 16)
                    if hexlitcp & 0x04000000 > 0:
                        opt2.append("opt+")
                    if "wscale" in optiondict:
                        if int(optiondict["wscale"]) > 14:
                            opt2.append("exws")
					#TODO: bad (malformed TCP option)
                    sig += ",".join(opt2) 
                else:
                    sig += "*"
                sig += ":0" # TODO: look for packet classes to implement other cases
            pkt_sign.flag = flag
            pkt_sign.protocol = proto
            pkt_sign.signature = sig
            pkt_sign.packet_type = pkttype
            return pkt_sign

    def reasig(self, sig_base, sig_pkt):
        """
            Compute signature base's wildcard with the signature's packet.
            	in(1): (string) p0f signature to be compared.
           		in(2): (string) pkt's signature to be compared with p0f's one.
				out: adapted signature.
        """
        sig1 = sig_base.split(":")
        sig2 = sig_pkt.split(":")
        for i in range(len(sig1)):
            if i >= len(sig2):
                break
            if sig1[i] == "*":
                sig1[i] = sig2[i]
            elif "mss*" in sig1[i] and sig2[3] !="":
                cols = sig1[i].split(",")
                cols2 = sig2[i].split(",")
                operand = int(cols[0].strip("mss*"))
                result = int(sig2[3]) * operand
                sig1[i] = str(result)
                if len(cols) == 2:
                    if cols[1] == "*" and len(cols2) == 2:
                        cols[1] = cols2[1]
                    sig1[i] += "," + cols[1]
            elif sig1[i] == "64-":
                if int(sig1[i][:2]) > int(sig2[i]):
                    sig1[i] = sig2[i]
            commas1 = sig1[i].split(",")
            commas2 = sig2[i].split(",")
            rcstr = []
            for j in range(len(commas1)):
                if j >= len(commas2):
                    break
                if commas1 == "*":
                    rcstr.append(commas2[j])
                else:
                    rcstr.append(commas1[j])
            sig1[i] = ",".join(rcstr)
        return ":".join(sig1)

    def calcpktdist(self, sig_base, sig_pkt, method=0):
        """
            Generique method to calculate distances between p0f conventional signatures.
            	in(1): (string) p0f signature to be compared.
            	in(2): (string) pkt's signature to be compared.
            	optional in(3): (int) method - by default => 0.
				out: distance calculated by a choosen method (default: levenshtein -> beta)
        """
        result = None
        oldsig = sig_base
        sig_base = self.reasig(sig_base, sig_pkt)
        if method == 0: # use Leveinstein by default (this is a beta test and lazy comparaison method on a whole signature)
            result = Levenshtein.distance(sig_base, sig_pkt)
        #TODO: other methods
        return result, sig_base
	
    def calchttptdist(self, sig_base, sig_pkt, method=0):
        result = None
        nsig_base, nsig_pkt = self.reaghttp(sig_base, sig_pkt)
        if method == 0:
            result = Levenshtein.distance(nsig_base, nsig_pkt)
        return result, nsig_base 
        
    def matchsig(self, pkt_sign):
        """
            Find the best match.
            	in(1): (tuple) pkt signature tuple.
                out: (distance, label, wildcarded_sig, orig_base_sig, [top 3 sigs: useful if the distance is too far].
        """
        sigtuple = None
        if pkt_sign is not None:
            sigtuple = (pkt_sign.flag, pkt_sign.protocol, pkt_sign.signature, pkt_sign.packet_type)
        if self.__fpobj is None:
            self.parse_p0fconf()
        bestsig = None
        top3sig = []
        if sigtuple is not None:
            sigtype=None # by default
            distfunc = self.calcpktdist
            if sigtuple[0] == 0x18: # TODO: more processing methods
                if sigtuple[3] == "http-response":
                    sigtype = "http:response"
                    distfunc = self.calchttptdist
                elif sigtuple[3] == "http-request":
                    sigtype = "http:request"
                    distfunc = self.calchttptdist
            else:
                if (sigtuple[0] & 0x2 > 0) and (sigtuple[0] & 0b10000 > 0) and sigtuple[1] == 0x6: # TCP response packet
                    sigtype = "tcp:response"
                elif (sigtuple[0] & 0x2 > 0) and (sigtuple[0] & 0b10000 == 0) and sigtuple[1] == 0x6: # TCP request packet
                    sigtype="tcp:request" # by default
            sig = sigtuple[2]
            if sigtype is not None:
                for label in self.__fpobj[sigtype]:
                    for s in self.__fpobj[sigtype][label]:
                        curdist, oldsig = distfunc(s, sig)
                        if bestsig is None or bestsig.distance >= curdist:
                            if bestsig is None:
                                bestsig = ClassifiedSignature()
                                bestsig.orig = sig
                            if len(top3sig) >= 3:
                                del top3sig[2]
                                top3sig.insert(0, {"sig":s, "label":label, "distance":curdist})
                            else:
                                top3sig.append({"sig":s, "label":label, "distance":curdist})
                            bestsig.distance = curdist
                            bestsig.label = label
                            bestsig.signature = s
                            bestsig.computedsig = oldsig
                            bestsig.top3 = top3sig
        return bestsig
