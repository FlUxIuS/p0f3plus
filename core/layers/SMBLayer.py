#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# SMB scapy Layer by FlUxIuS 
# remade the wheel a little, but smb.py is a bit buggy at the moment... or I don't know how this works! :D

from scapy.packet import *
from scapy.fields import *

NBIOS_messagetype = { 0x00 : "Session Message" }
SMB_command = { 0x73 : "Session Setup AndX" }
NT_status = { 0xc0000016 : "STATUS_MORE_PROCESSING_REQUIRED" }
andXcommand = { 0xff : "No further commands" }
negResult_list = { 0x01 : "accept-incomplete" }
NTLM_message_type = { 0x00000002 : "NTLMSSP_CHALLENGE" }

itemtype_list = {
    0x0001 : "NetBIOS computer name",
    0x0002 : "NetBIOS domain name",
    0x0003 : "DNS computer name",
    0x0004 : "DNS domaine name",
    0x0007 : "Timestamp",
}

class TIAttribute(Packet):
    name = "TIAttribute "
    fields_desc=[
        LEShortEnumField("ItemType", 0x0002, itemtype_list),
        LEShortField("ItemLength", 0x0600),
        StrLenField("ItemName", None, length_from=lambda pkt:pkt.ItemLength),
    ]

    def extract_padding(self, p):
        return "", p

class NTLMTargetInfo(Packet):
    name = "NTLMTargetInfo "
    fields_desc=[
        LEShortField("Length", 0x0600),
        LEShortField("Maxlen", 0x0600),
        LEIntField("Offset", 0x0600),
        ByteField("MajorVersion", 6),
        ByteField("MajorVersion", 3),
        LEShortField("BuildNumber", 9600),
        X3BytesField("numpad", 0),
        ByteField("CurrentRevision", 15),
        StrFixedLenField("TargetName", "\x53\x00\x43\x00\x56\x00", 6),
        PacketListField("TIAttributes", None, TIAttribute, length_from=lambda pkt:pkt.Length-4),
        StrFixedLenField("End_of_list", "\x00"*4, 4),
    ]

    def extract_padding(self, p):
        return "", p

class NTLMSecureServiceProvider(Packet):
    name = "NTLMSecureServiceProvider "
    fields_desc=[
        StrFixedLenField("identifier", "NTLMSSP\x00", 8),
        LEIntEnumField("MessageType", 0x00000002, NTLM_message_type),
        LEShortField("Length", 0x0600),
        LEShortField("Maxlen", 0x0600),
        LEIntField("Offset", 0x0600),
        LEIntField("NegotiateFlag", 0xe28a8215),
        StrFixedLenField("NTLMServerChallenge", "\x00"*8, 8),
        StrFixedLenField("reserved", "\x00"*8, 8),
        PacketField("TargetInfo", None, NTLMTargetInfo),
    ]
    
    def extract_padding(self, p):
        return "", p

class SSAXR_SBlob(Packet):
    name = "SSAXR_SBlob "
    fields_desc=[
        StrFixedLenField("SPNpad", "\x00"*10, 10),
        ByteEnumField("negResult", 0x01, negResult_list),
        StrFixedLenField("SPNpad2", "\x00"*4, 4),
        StrFixedLenField("supportMech", "\x00"*10, 10),
        StrFixedLenField("SPNpad3", "\x00"*4, 4),
        ConditionalField(PacketField("responseToken", None, NTLMSecureServiceProvider),
            lambda pkt:pkt.supportMech == "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"), 
    ]
    
    def extract_padding(self, p):
        return "", p

class SessionSetupAndXRequest(Packet):
    name = "SessionSetupAndXRequest "
    fields_desc=[
        ByteField("WordCount", 4),
        ByteEnumField("AndXCommand", 0xff, andXcommand),
        ByteField("Reserved", 0),
        LEShortField("AndXOffset", 379),
        ShortField("MaxBuffer", 0),
        ShortField("MaxMpxCount", 0),
        ShortField("VCNumber", 0),
        XIntField("SessionKey", 0),
        FieldLenField("SecurityBlobLength", None, count_of="NBdata", fmt="<H"),
        XIntField("Reserved2", 0),
        XIntField("Capabilities", 0),
        LEShortField("ByteCount", 0x0000),
        PacketListField("SecureBlobContent", None, SSAXR_SBlob, length_from=lambda pkt:pkt.SecurityBlobLength),
        StrFixedLenField("NativeOS", "\x00"*34, 34),
        StrFixedLenField("NativeLANManager", "\x00"*36, 36),
    ]

    def extract_padding(self, p):
        return "", p

class SessionSetupAndXResponse(Packet):
    name = "SessionSetupAndXResponse "
    fields_desc=[
        ByteField("WordCount", 4),
        ByteEnumField("AndXCommand", 0xff, andXcommand),
        ByteField("Reserved", 0),
        LEShortField("AndXOffset", 379),
        ShortField("Action", 0),
        FieldLenField("SecurityBlobLength", None, count_of="NBdata", fmt="<H"),
        LEShortField("ByteCount", 0x0000),
        PacketListField("SecureBlobContent", None, SSAXR_SBlob, length_from=lambda pkt:pkt.SecurityBlobLength),
        StrFixedLenField("NativeOS", "\x00"*34, 34),
        StrFixedLenField("NativeLANManager", "\x00"*36, 36),
    ]

    def extract_padding(self, p):
        return "", p

class SMBHead(Packet):
    name = "SMBHead "
    fields_desc=[
        ByteEnumField("Command", 0x73, NBIOS_messagetype),
        LEIntEnumField("NT_Status", 0, NT_status),
        ByteField("Flags", 0x98),
        LEShortField("Flags2", 0),
        ShortField("ProcessIDHigh", 0),
        StrFixedLenField("Signature", "\x00"*8, 8),
        ShortField("Reserved", 0),
        ShortField("TreeID", 0),
        ShortField("ProcessID", 0),
        ShortField("UserID", 0),
        ShortField("MultiplexID", 0),
        ConditionalField(PacketField("SSAXP", None, SessionSetupAndXResponse),
            lambda pkt:pkt.Command == 0x73 and (pkt.Flags >> 7) == 1),
        ConditionalField(PacketField("SSAXPR", None, SessionSetupAndXRequest),
            lambda pkt:pkt.Command == 0x73 and (pkt.Flags >> 7) == 0),
    ]

    def extract_padding(self, p):
        return "", p

class NB_header(Packet):
    name = "NB_header "
    fields_desc=[
        StrFixedLenField("header", "\xff\x53\x4d\x42", 4),
        ConditionalField(PacketField("SMBP", None, SMBHead),
            lambda pkt:pkt.header == b"\xff\x53\x4d\x42"),
    ] 

    def extract_padding(self, p):
        return "", p

class NetBIOS(Packet):
    name = "NetBIOS "
    fields_desc=[
        ByteEnumField("Message Type", 0x00, NBIOS_messagetype),
        X3BytesField("Length", 0),
        PacketField("NBdata", None, NB_header),
    ]
