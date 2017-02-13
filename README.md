# p0f3plus
A native passive and unofficial implementation of p0f3 in Python

## Dependencies

- Python 2 or 3
- Scapy (use Scapy for Python3 if you prefer Python3)

## Fingerprint a PCAP file

To fingerprint a PCAP file, the `pcaprint.py` can be used in two different ways:

* the classic way that printis each frames like p0f3 do;
* or to aggregate services in a XML.

Additionnal information are added to p0f3 signatures if some data are 
identified in packets. These information include HTTP or SMB headers
(other features can be implemented).

## Why I should use this tool?

This tool is slow compared to the original C implementation of p0f3, but can be
used to identify packets, and be extend very quickly with useful features that 
use also data contained in the packets. 

Originally, this tool was developped because the p0f implementation in Scapy is
obsolete with p0f3 signatures, and these signatures where needed as an additionnal
way to identify an OS, or/and a service.  

### Quick run

#### Output in XML

To p0f3 with the default script `pcaprint.py` against a PCAP to output an XML,
you can use the following command:

```
python3 ./pcaprint.py -c capture.pcapng -o test.xml
```

As a results, you'll see a basic XML files that contains information for each IP address
as follows:

```
     <host>
        <address addrtype="ipv4">XXX.XXX.XXX.38</address>
        <hostnames/>
        <applications>
          <application>
            <appname>X2S_Platform</appname>
            <version/>
            <sport>80</sport>
          </application>
        </applications>
        <matches>
          <bests>
            <best>
              <version>3.x</version>
              <label>s:unix:Linux:3.x</label>
              <type>unix</type>
              <distance>2</distance>
              <os>Linux</os>
            </best>
            <best>
              <version>2.x</version>
              <label>s:!:Apache:2.x</label>
              <type>!</type>
              <distance>103</distance>
              <os>Apache</os>
            </best>
            [...]
          </bests>
        </matches>
    </host>
    [...]
    <host>
        <address addrtype="ipv4">XXX.XXX.XXX.102</address>
        <hostnames>
          <hostname>XXXXX.com.</hostname>
        </hostnames>
        <applications>
          <application>
            <appname>nginx</appname>
            <version/>
            <sport>80</sport>
          </application>
        </applications>
        <matches>
          <bests>
            <best>
              <version>2.6.x</version>
              <label>s:unix:Linux:2.6.x</label>
              <type>unix</type>
              <distance>4</distance>
              <os>Linux</os>
            </best>
            [...]
         </bests>
        </matches>
       [...]
    <host>
        <address addrtype="ipv4">10.0.0.13</address>
        <hostnames/>
        <applications>
          <application>
            <appname>AndroidSDK_21_klte_5</appname>
            <version>.0</version>
            <sport>52277</sport>
          </application>
    [...] 
```

#### The classic p0f way

If you're nostalgic and want to print the PCAP pretty like p0f3 do, you can run
the following command:

```
.-[TCP XXX.XXX.XXX.XXX/80 -> 10.11.10.136/48370 (push+ack)]-
|---(packet payload fingerprints)
|   os: Debian
|   version: 2.2.22
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

## Contributions

A lot of work need to be done, this tool needs more features to identify packets, an IPv6 support, and so on. 
This project is also opened for suggestions, so any contribution is welcomed :) 
