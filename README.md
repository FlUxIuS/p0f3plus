# p0f3plus
A native and unofficial implementation of p0f3 in Python with extra analysis features: It's p0f+

## Dependencies

- Python 2 or 3
- Scapy (use Scapy for Python3 if you prefer Python3)

## Fingerprint a PCAP file

To fingerprint a PCAP file, the `pcaprint.py` can be used in two different ways:

* the classic way that prints each frames like p0f3 do;
* or to aggregate services in a nmap XML file like.

Additionnal information are added to p0f3 signatures if some data are 
identified in packets. These information include HTTP or SMB headers
(other features can be implemented).

## Why I should use this tool?

This tool is slow compared to the original C implementation of p0f3, but can be
used to identify packets, and can be extend very quickly with useful features that 
use payloads contained in the packets. 

Originally, this tool was developped because the p0f implementation in Scapy is
obsolete with p0f3 signatures, and these signatures were needed as a backup
way to identify an OS, or/and a service.  

### Quick run

#### Output in XML

To p0f3 with the default script `pcaprint.py` against a PCAP to output a nmap XML (beta),
you can use the following command:

```
python3 ./pcaprint.py -c capture.pcapng -o test.xml
```

As a results, you'll see a basic XML files that contains information for each IP address
as follows:

```
$ python3 ./pcaprint.py -c capture.pcapng -o output.xml
<?xml version="1.0" ?>
  <?xml-stylesheet type="text/xsl" href="file:///usr/local/bin/../share/nmap/nmap.xsl"?>
  <nmaprun scanner="p0fplus" start="1488468846" startstr="Thu Mar 2 16:34:06 2017">
    <host>
      <address addrtype="ipv4" ipaddr="172.XXX.XXX.XXX"/>
      <hostnames/>
      <ports>
        <port portid="39428" protocol="tcp">
          <state reason="push-ack" state="open"/>
          <service extrainfo="Debian" product="OpenSSH" version="7.3p1"/>
        </port>
      </ports>
      <os>
        <osmatch accuracy="100" name="Linux 3.11 and newer">
          <osclass accuracy="100" osfamily="Linux" osgen="3.11 and newer"/>
        </osmatch>
        <osmatch accuracy="99" name="Linux 2.2">
          <osclass accuracy="99" osfamily="Linux" osgen="2.2.x"/>
        </osmatch>
      </os>
    </host>
    <host>
      <address addrtype="ipv4" ipaddr="XXX.XXX.XXX.12"/>
      <hostnames/>
      <ports>
        <port portid="443" protocol="tcp">
          <state reason="ack" state="open"/>
        </port>
      </ports>
    </host>
    <host>
      <address addrtype="ipv4" ipaddr="104.16.26.235"/>
      <hostnames/>
      <ports>
        <port portid="443" protocol="tcp">
          <state reason="syn-ack" state="open"/>
        </port>
      </ports>
      <os>
        <osmatch accuracy="94" name="Linux 2.6">
          <osclass accuracy="94" osfamily="Linux" osgen="2.6.x"/>
        </osmatch>
        <osmatch accuracy="94" name="Linux 3">
          <osclass accuracy="94" osfamily="Linux" osgen="3.x"/>
        </osmatch>
      </os>
    </host>
    <host>
      <address addrtype="ipv4" ipaddr="104.16.118.182"/>
      <hostnames>
        <hostname name="stackexchange.com"/>
        <hostname name="christianity.stackexchange.com"/>
        <hostname name="money.stackexchange.com"/>
        <hostname name="puzzling.stackexchange.com"/>
        <hostname name="rpg.stackexchange.com"/>
        <hostname name="tex.stackexchange.com"/>
        <hostname name="webapps.stackexchange.com"/>
        <hostname name="workplace.stackexchange.com"/>
        <hostname name="3dprinting.stackexchange.com"/>
        <hostname name="astronomy.stackexchange.com"/>
        <hostname name="biology.stackexchange.com"/>
        <hostname name="blender.stackexchange.com"/>
        <hostname name="chemistry.stackexchange.com"/>
        <hostname name="expressionengine.stackexchange.com"/>
      </hostnames>
    </host>
    <host>
      <address addrtype="ipv4" ipaddr="216.XXX.XXX.XXX"/>
      <hostnames/>
      <ports>
        <port portid="80" protocol="tcp">
          <state reason="push-ack" state="open"/>
          <service extrainfo="" product="cafe" version=""/>
        </port>
      </ports>
      <os>
        <osmatch accuracy="92" name="Linux 2.6">
          <osclass accuracy="92" osfamily="Linux" osgen="2.6.x"/>
        </osmatch>
        <osmatch accuracy="92" name="Linux 3">
          <osclass accuracy="92" osfamily="Linux" osgen="3.x"/>
        </osmatch>
      </os>
    </host>
    [...]
    <host>
      <address addrtype="ipv4" ipaddr="XXX.XXX.XXX.XXX"/>
      <hostnames/>
      <ports>
        <port portid="6526" protocol="tcp">
          <state reason="push-ack" state="open"/>
          <service extrainfo="" product="OpenSSH" version="6.7p1"/>
        </port>
      </ports>
      <os>
        <osmatch accuracy="99" name="Linux 3">
          <osclass accuracy="99" osfamily="Linux" osgen="3.x"/>
        </osmatch>
      </os>
    </host>
  </nmaprun>
```

#### The classic p0f way

If you're nostalgic and want to print the PCAP pretty like p0f3 do, you can run
the following command:

```
$ python3 ./pcaprint.py -c capture.pcapng -p

.-[TCP XXX.XXX.XXX.XXX/80 -> 10.11.10.136/48370 (push+ack)]-
|---(packet payload fingerprints)
|   os: Debian
|   version: 2.222
|   allow: GET,HEAD,POST,OPTIONS
|   application: Apache
|---(p0f signatures)
|   label= s:!:Apache:2.x
|   best guess sig= 1:Date,Server,?Last-Modified,?Accept-Ranges=[bytes],?Content-Length,?Connection=[close],?Transfer-Encoding=[chunked],Content-Type:Keep-Alive:Apache
|   original sig= 1:Date,Server,Allow,Vary,Content-Length,Connection=[close],Content-Type:*:Apache
|   sig computed= 1:Date,Server,Content-Length,Connection=[close],Content-Type:Keep-Alive:Apache
|   distance= 11
|   Distance too long! other guesses=>
|       Top1= sig:1:Date,Server,?Last-Modified,?Accept-Ranges=[bytes],?Content-Length,?Content-Range,Keep-Alive=[timeout],Connection=[Keep-Alive],?Transfer-Encoding=[chunked],Content-Type::Apache, label:s:!:Apache:2.x
|       Top2= sig:1:Date,Server,?Last-Modified,?Accept-Ranges=[bytes],?Content-Length,?Connection=[close],?Transfer-Encoding=[chunked],Content-Type:Keep-Alive:Apache, label:s:!:Apache:2.x
`----

P 10.11.10.136/52244 -> XXX.XXX.XXX.XXX/2013 (syn)]-
|---(p0f signatures)
|   label= s:!:NMap:SYN scan
|   best guess sig= *:64-:0:1460:1024,0:mss::0
|   original sig= 4:38:0:1460:1024:mss::0
|   sig computed= 4:38:0:1460:1024:mss::0
|   distance= 0
`----

.-[TCP 10.11.10.136/47220 -> XXX.XXX.XXX.XXX/443 (syn)]-
|---(p0f signatures)
|   label= s:unix:Linux:3.11 and newer
|   best guess sig= *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
|   original sig= 4:64:0:1460:29200,10:mss,sok,ts,nop,ws:df,id+:0
|   sig computed= 4:64:0:1460:29200,10:mss,sok,ts,nop,ws:df,id+:0
|   distance= 0
`----

.-[TCP XXX.XXX.XXX.XXX/443 -> 10.11.10.136/47220 (syn+ack)]-
|---(p0f signatures)
|   label= s:unix:Linux:3.x
|   best guess sig= *:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df:0
|   original sig= 4:55:0:1448:14480,5:mss,sok,ts,nop,ws:df:0
|   sig computed= 4:64:0:1448:14480,5:mss,sok,ts,nop,ws:df:0
|   distance= 2
`----
```
## Use the API

You can add the project in your Python library path, then p0f3plus's methods as follows to identify a packet:

```python
from p0f3p.core.p0f3p import *

a = p0f3p()
packet = '\x00\xba\xd0\xc0\xff\xee@Z\x9b\xe8\xdb\x91\x08\x00E\x00\x015\x0b @\x007\x06\x99\x07h\x10!\xf9BBBB\x00P\xb7t\xa4\xf0\x1d\x0c\x1c{\xcb\x9bP\x18\x00 v\xdd\x00\x00HTTP/1.1 204 No Content\r\nDate: Thu, 21 Apr 2016 11:08:56 GMT\r\nConnection: keep-alive\r\nCache-Control: private\r\nPragma: no-cache\r\nX-Frame-Options: SAMEORIGIN\r\nX-Request-Guid: 2f5dfddc-1d7a-45d7-a739-00584d917948\r\nServer: cloudflare-nginx\r\nCF-RAY: 29706181e6ee102b-CDG\r\n\r\n'
pktsign = a.pkt2sig(Ether(packet)) # transforms it to 'PacketSignature' object. Value of pktsign.signature = '1:Date,Connection=[keep-alive],Cache-Control,Pragma,X-Frame-Options,X-Request-Guid,Server,CF-RAY:*:cloudflare'
matches = a.matchsig(pktsign) # Gets matches in a 'ClassifiedSignature' object. The computed signature before the matching is '1:Date,Server,Connection=[Keep-Alive],Keep-Alive=[timeout]:Content-Type,Accept-Ranges:Apache'. The best match is '1:Date,Server,Connection=[Keep-Alive],Keep-Alive=[timeout]:Content-Type,Accept-Ranges:Apache' and you can access to the top3, label, distance, etc. to perform your analysises.
```

## Contributions

A lot of work need to be done, this tool needs more features to identify packets, an IPv6 support, and so on. 
This project is also opened for suggestions, so any contribution is welcomed :) 
