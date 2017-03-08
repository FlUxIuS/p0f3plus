# -*- coding: utf-8 -*-
from __future__ import print_function
from xml.dom.minidom import Document
import os, sys
from core.p0f3p import *

def TCPshow(cap):
    p = p0f3p()
    tsig = p.pkt2sig(cap) # calculate the signature of the packet
    match = None
    if cap.haslayer("IP"):
        match = p.matchsig(tsig) # match packet's signature with another in the p0f3 database
    flag = None
    othervalue = None
    if (cap.haslayer("IP") or cap.haslayer("IPv6")) and cap.haslayer("TCP"):
        if cap.haslayer("IP"):
            ippart = cap["IP"]
        else:
            ippart = cap["IPv6"]
        if cap["TCP"].flags == 0x18: # push-ack contain much more information
            flag = "push+ack"
        else:
            if (tsig.flag & 0x2 > 0) and (tsig.flag & 0b10000 == 0): # SYN flag 
                flag = "syn"
            elif tsig.flag & 0b10000 > 0: # SYN-ACK flag
                flag = "syn+ack"
        if tsig.extra is None and match is None:
            return 
        print(".-[TCP %s/%s -> %s/%s (%s)]-" % (ippart.src, ippart.sport, ippart.dst, ippart.dport, flag))
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
        if (cap.haslayer("IP") or cap.haslayer("IPv6")) and cap.haslayer("TCP"):
            tsig = p.pkt2sig(cap)
            match = None
            if cap.haslayer("IP"):
                match = p.matchsig(tsig)
                ippart = cap["IP"]
            else:
                ippart = cap["IPv6"]
            if ippart.src not in hosts:
                hosts[ippart.src] = {"applications":[],
                                        "matches":{},
                                        "os":None,
                                        "hostnames":None,
                                        "otherports": {}}
                if ippart.sport not in hosts[ippart.src]["otherports"]:
                    hosts[ippart.src]["otherports"][ippart.sport] = {'flag':cap['TCP'].flags, 'matched':False}
            if tsig.extra is not None and type(tsig.extra).__name__ == "dict":
                if "os" in tsig.extra:
                    hosts[ippart.src]["os"] = tsig.extra["os"]
                if "application" in tsig.extra:
                    filt = list(filter(lambda app: app['appname'] == tsig.extra["application"], hosts[ippart.src]["applications"]))
                    if len(filt) == 0:
                        if ippart.sport in hosts[ippart.src]["otherports"]:
                            hosts[ippart.src]["otherports"][ippart.sport]['matched'] = True
                        extrainfo = None
                        if "os" in tsig.extra:
                            extrainfo = tsig.extra['os']
                        hosts[ippart.src]["applications"].append({ "version" : tsig.extra["version"],
                                                                      "sport" : ippart.sport,
                                                                      "extrainf" : extrainfo,
                                                                      "apptype" : tsig.extra["apptype"],
                                                                      "appname" : tsig.extra["application"] })
                    elif len(filt) == 1:
                        if filt[0]['extrainf'] is None and 'os' in tsig.extra:
                            if tsig.extra['os'] is not None:
                                extrainfo = ''
                                for k,v in tsig.extra.items():
                                    if extrainfo != '':
                                        extrainfo += ' '
                                    if v is not None:
                                        extrainfo += "%s:%s" % (k,v)    
                                id_ = hosts[ippart.src]["applications"].index(filt[0])
                                hosts[ippart.src]["applications"][id_]['extrainf'] = extrainfo
                        
            if match is not None:
                if "bests" not in hosts[ippart.src]["matches"]:
                    hosts[ippart.src]["matches"]["bests"] = []
                filt = list(filter(lambda best: best['label'] == match.label, hosts[ippart.src]["matches"]["bests"]))
                _, mtype, mos, mver = match.label.split(":")
                if len(filt) == 0:
                    hosts[ippart.src]["matches"]["bests"].append({    "label":match.label,
                                                                "distance":match.distance,
                                                                "type":mtype,
                                                                "os":mos,
                                                                "version":mver, })
                for top in match.top3:
                    if "guesses" not in hosts[ippart.src]["matches"]:
                        hosts[ippart.src]["matches"]["guesses"] = []
                    filt = list(filter(lambda guess: guess['label'] == top["label"], hosts[ippart.src]["matches"]["guesses"]))
                    if len(filt) == 0:
                        _, systype, sysos, sysver = top["label"].split(":") 
                        hosts[ippart.src]["matches"]["guesses"].append({
                            "label":top["label"], 
                            "distance":top["distance"],
                            "version":sysver,
                            "type":systype,
                            "os":sysos,})
        elif cap.haslayer("IP") and cap.haslayer("DNSRR"): # resolve hosts
            if cap[DNSRR].type == 1:
                ipreq = convB2Str(cap[DNSRR].rdata)
                domainreq = convB2Str(cap[DNSRR].rrname)
                if ipreq not in hosts:
                    hosts[ipreq] = {"applications":[],
                                    "matches":{},
                                    "os":None,
                                    "hostnames":None,
                                    "otherports":{}
                                    }
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

flagslist = {
    0x2 : 'syn',
    0x10 : 'ack',
    0x12 : 'syn-ack',
    0x18 : 'push-ack',
}

def flag2str(flag):
    if flag in flagslist:
        return flagslist[flag]
    else:
        return

def exportNmapXML(pcap, out='nmapout-p0f3p.xml', retdom=False):
    import time
    doc = Document()
    pyobj = processCaptures(pcap)
    root = doc.createElement('nmaprun')
    pi = doc.createProcessingInstruction('xml-stylesheet',
                                     'type="text/xsl" href="file:///usr/local/bin/../share/nmap/nmap.xsl"')
    first = doc.firstChild
    doc.insertBefore(pi, first)
    root.setAttribute('scanner', 'p0fplus')
    t = int(time.time())
    root.setAttribute('start', str(t))
    ftime = time.ctime(t)
    root.setAttribute('startstr', ftime.replace('  ',' '))
    doc.appendChild(root)
    for k,v in pyobj.items():
        host = doc.createElement('host')
        root.appendChild(host)
        addr = doc.createElement('address')
        addr.setAttribute('addrtype', 'ipv4')
        k = convB2Str(k)
        addr.setAttribute('ipaddr', k)
        host.appendChild(addr)
        hostnames = doc.createElement('hostnames')
        host.appendChild(hostnames)
        if v['hostnames'] is not None:
            for h in v['hostnames']:
                hostname = doc.createElement('hostname') 
                if h[-1] == '.':
                    h = h[:-1]
                hostname.setAttribute('name', h)
                hostnames.appendChild(hostname)
        ports = None
        if v['applications'] is not None:
            for app in v['applications']:
                if 'sport' in app:
                    ports = doc.createElement('ports')
                    host.appendChild(ports)
                    port = doc.createElement('port')
                    port.setAttribute('protocol', 'tcp') # FIXME: change when UDP is supported
                    port.setAttribute('portid', str(app['sport']))
                    ports.appendChild(port)
                    state = doc.createElement('state')
                    state.setAttribute('state', 'open')
                    state.setAttribute('reason', 'push-ack')
                    port.appendChild(state)
                    service = doc.createElement('service')
                    if 'appname' in app:
                        service.setAttribute('product',app['appname'])
                    if 'version' in app:
                        service.setAttribute('version', app['version'])
                    if 'extrainf' in app:
                        service.setAttribute('extrainfo', app['extrainf'])
                    port.appendChild(service)
        if v['otherports'] is not None:
            for portk, value in v['otherports'].items():
                if value['matched'] is False:
                    if ports is None:
                        ports = doc.createElement('ports')
                        host.appendChild(ports)
                    port = doc.createElement('port')
                    port.setAttribute('protocol', 'tcp')
                    port.setAttribute('portid', str(portk))
                    ports.appendChild(port)
                    state = doc.createElement('state')
                    state.setAttribute('state', 'open')
                    reasonstr = flag2str(value['flag'])
                    if reasonstr is not None:
                        state.setAttribute('reason', reasonstr)
                    port.appendChild(state) 
        if 'guesses' in v['matches']:
            os = doc.createElement('os')
            host.appendChild(os)
            osmatch = doc.createElement('osmatch')
            for guess in v['matches']['guesses']:
                if guess['type'] != '!': #is a system
                    osmatch = doc.createElement('osmatch')
                    namematch = ' '.join(guess['label'].split(':')[2:]).replace('.x', '')
                    osmatch.setAttribute('name', namematch)
                    accuracy = str(100-guess['distance']) # best formula ever!
                    osmatch.setAttribute('accuracy', accuracy)
                    os.appendChild(osmatch)
                    osclass = doc.createElement('osclass')
                    osclass.setAttribute('osfamily', guess['os'])
                    osclass.setAttribute('osgen', guess['version'])
                    osclass.setAttribute('accuracy', accuracy)
                    osmatch.appendChild(osclass)
    if retdom is True:
        return doc # return only the minidom object
    else:
        doc.writexml( open(out, 'w'),
                   indent="  ",
                   addindent="  ",
                   newl='\n')

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
