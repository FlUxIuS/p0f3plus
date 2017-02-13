# -*- coding: utf-8 -*-
from __future__ import print_function
from core.p0f3p import *
from xml.dom.minidom import Document

def TCPshow(cap):
    p = p0f3p()
    tsig = p.pkt2sig(cap) # calculate the signature of the packet
    match = p.matchsig(tsig) # match packet's signature with another in the p0f3 database
    flag = None
    othervalue = None
    if cap.haslayer("IP") and cap.haslayer("TCP"):
        if cap["TCP"].flags == 0x18: # push-ack contain much more information
            flag = "push+ack"
        else:
            if (tsig.flag & 0x2 > 0) and (tsig.flag & 0b10000 == 0): # SYN flag 
                flag = "syn"
            elif tsig.flag & 0b10000 > 0: # SYN-ACK flag
                flag = "syn+ack"
        if tsig.extra is None and match is None:
            return 
        print(".-[TCP %s/%s -> %s/%s (%s)]-" % (cap["IP"].src, cap["IP"].sport, cap["IP"].dst, cap["IP"].dport, flag))
        if tsig.extra is not None and type(tsig.extra).__name__ == "dict":
            print("|---(packet payload fingerprints)")
            for key, value in tsig.extra.items():
                print("|\t%s: %s" % (key, value))
        if match is not None:
            print("|---(p0f signatures)")
            print("|\tlabel=", match.label)
            print("|\tbest guess sig=", match.signature)
            print("|\toriginal sig=", match.orig)
            print("|\tsig computed=", match.computedsig)
            print("|\tdistance=", match.distance)
            if int(match.distance) > 10:
                print("|\tDistance too long! other guesses=>")
                countop = 0
                for top in match.top3:
                    countop += 1
                    print("|\t\tTop%i= sig:%s, label:%s" % (countop ,top["sig"], top["label"]))
        print("`----\n")

def convB2Str(string):
    if type(string).__name__ == "bytes":
        string = string.decode("utf-8", "ignore")
    return string

def processCaptures(pcap):
    p = p0f3p()
    hosts = {}
    for cap in pcap:
        flag = "unknown"
        othervalue = None
        if cap.haslayer("IP") and cap.haslayer("TCP"):
            tsig = p.pkt2sig(cap)
            match = p.matchsig(tsig)
            if cap["IP"].src not in hosts:
                hosts[cap["IP"].src] = {"applications":[],
                                        "matches":{},
                                        "os":None,
                                        "hostnames":None}
            if tsig.extra is not None and type(tsig.extra).__name__ == "dict":
                if "os" in tsig.extra:
                    hosts[cap["IP"].src]["os"] = tsig.extra["os"]
                if "application" in tsig.extra:
                    filt = list(filter(lambda app: app['appname'] == tsig.extra["application"], hosts[cap["IP"].src]["applications"]))
                    if len(filt) == 0:
                        hosts[cap["IP"].src]["applications"].append({ "version" : tsig.extra["version"],
                                                                      "sport" : cap["IP"].sport,
                                                                      "appname" : tsig.extra["application"] })
            if match is not None:
                if "bests" not in hosts[cap["IP"].src]["matches"]:
                    hosts[cap["IP"].src]["matches"]["bests"] = []
                filt = list(filter(lambda best: best['label'] == match.label, hosts[cap["IP"].src]["matches"]["bests"]))
                _, mtype, mos, mver = match.label.split(":")
                if len(filt) == 0:
                    hosts[cap["IP"].src]["matches"]["bests"].append({    "label":match.label,
                                                                "distance":match.distance,
                                                                "type":mtype,
                                                                "os":mos,
                                                                "version":mver, })
                for top in match.top3:
                    if "guesses" not in hosts[cap["IP"].src]["matches"]:
                        hosts[cap["IP"].src]["matches"]["guesses"] = []
                    filt = list(filter(lambda guess: guess['label'] == top["label"], hosts[cap["IP"].src]["matches"]["guesses"]))
                    if len(filt) == 0:
                        _, systype, sysos, sysver = top["label"].split(":") 
                        hosts[cap["IP"].src]["matches"]["guesses"].append({
                            "label":top["label"], 
                            "distance":top["distance"],
                            "version":sysver,
                            "type":systype,
                            "os":sysos,})
        elif cap.haslayer("IP") and cap.haslayer("DNSRR"): # resolve hosts
            ipreq = convB2Str(cap[DNSRR].rdata)
            domainreq = convB2Str(cap[DNSRR].rrname)
            if ipreq not in hosts:
                hosts[ipreq] = {"applications":[],
                                "matches":{},
                                "os":None,
                                "hostnames":None}
            if hosts[ipreq]["hostnames"] is None:
                hosts[ipreq]["hostnames"] = []
            if domainreq not in hosts[ipreq]["hostnames"]:
                hosts[ipreq]["hostnames"].append(domainreq)
    return hosts

def recursechild(doc, parent, pyobj):
    for k,v in pyobj.items():
        ne = doc.createElement(k)
        parent.appendChild(ne)
        if type(v).__name__ == "dict":
            recursechild(doc, ne, v)
        elif type(v).__name__ == "str" or type(v).__name__ == "int":
            value = doc.createTextNode(str(v))
            ne.appendChild(value)
        elif type(v).__name__ == "list":
            for i in v:
                subelstr = k[:-1]
                if "guesses" in k:
                    subelstr = "match"
                subel = doc.createElement(subelstr)
                ne.appendChild(subel)
                if type(i).__name__ == "dict":
                    recursechild(doc, subel, i)
                elif type(i).__name__ == "str":
                    svalue = doc.createTextNode(str(i))
                    subel.appendChild(svalue)

def exportXML(pcap, out="out-p0f3p.xml"):
    doc = Document()
    pyobj = processCaptures(pcap)
    root = doc.createElement("pcapanalysis")
    doc.appendChild(root)
    hosts = doc.createElement("hosts")
    root.appendChild(hosts)
    for k,v in pyobj.items():
        host = doc.createElement("host")
        hosts.appendChild(host)
        addr = doc.createElement("address")
        addr.setAttribute("addrtype", "ipv4") # for the moment we support only ipv4
        host.appendChild(addr)
        k = convB2Str(k)
        nodeText = doc.createTextNode(k)
        addr.appendChild(nodeText)
        if type(v).__name__ == "dict":
            recursechild(doc, host, v)
    doc.writexml( open(out, 'w'),
               indent="  ",
               addindent="  ",
               newl='\n')
