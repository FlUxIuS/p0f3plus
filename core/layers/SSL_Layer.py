#!/usr/local/bin/python
# -*- coding: utf-8 -*-

#
# SSL scapy Layer by FlUxIuS 
#

from scapy.all import *

SSLContentType = {
	0x14 : "'Change Cipher Spec'",
	0x16 : "'Handshake'",
}

SSLVersion = {
	0x0300 : "'SSL 3.0'",
	0x0303 : "'TLS 1.2'",
}

SSLHandshakeType = {
	0x01 : "'Client Hello'",
	0x04 : "'New Session Ticket'",
	0x02 : "'Server Hello'",
	0x0b : "'Certificate'",
	0x0c : "'Server Key Exchange'",
	0x0e : "'Server Hello Done'",
}

SSL_ciphersuite = {
	0x000000 : "TLS_NULL_WITH_NULL_NULL",
	0x000001 : "TLS_RSA_WITH_NULL_MD5",
	0x000002 : "TLS_RSA_WITH_NULL_SHA",
	0x000003 : "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x000004 : "TLS_RSA_WITH_RC4_128_MD5",
	0x000005 : "TLS_RSA_WITH_RC4_128_SHA",
	0x000006 : "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x000007 : "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x000008 : "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000009 : "TLS_RSA_WITH_DES_CBC_SHA",
	0x00000a : "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x00000b : "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x00000c : "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x00000d : "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x00000e : "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x00000f : "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x000010 : "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000011 : "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000012 : "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x000013 : "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000014 : "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000015 : "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x000016 : "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000017 : "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x000018 : "TLS_DH_anon_WITH_RC4_128_MD5",
	0x000019 : "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x00001a : "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x00001b : "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x00001c : "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
	0x00001d : "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
	0x00001e : "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA",
	0x00001E : "TLS_KRB5_WITH_DES_CBC_SHA",
	0x00001F : "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
	0x000020 : "TLS_KRB5_WITH_RC4_128_SHA",
	0x000021 : "TLS_KRB5_WITH_IDEA_CBC_SHA",
	0x000022 : "TLS_KRB5_WITH_DES_CBC_MD5",
	0x000023 : "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
	0x000024 : "TLS_KRB5_WITH_RC4_128_MD5",
	0x000025 : "TLS_KRB5_WITH_IDEA_CBC_MD5",
	0x000026 : "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
	0x000027 : "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
	0x000028 : "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
	0x000029 : "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
	0x00002A : "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
	0x00002B : "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
	0x00002C : "TLS_PSK_WITH_NULL_SHA",
	0x00002D : "TLS_DHE_PSK_WITH_NULL_SHA",
	0x00002E : "TLS_RSA_PSK_WITH_NULL_SHA",
	0x00002f : "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x000030 : "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x000031 : "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x000032 : "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x000033 : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x000034 : "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x000035 : "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x000036 : "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x000037 : "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x000038 : "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x000039 : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x00003A : "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x00003B : "TLS_RSA_WITH_NULL_SHA256",
	0x00003C : "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x00003D : "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x00003E : "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x00003F : "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x000040 : "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x000041 : "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x000042 : "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x000043 : "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x000044 : "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x000045 : "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x000046 : "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	0x000047 : "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0x000048 : "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0x000049 : "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA",
	0x00004A : "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0x00004B : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0x00004C : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0x000060 : "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
	0x000061 : "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
	0x000062 : "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
	0x000063 : "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
	0x000064 : "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
	0x000065 : "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
	0x000066 : "TLS_DHE_DSS_WITH_RC4_128_SHA",
	0x000067 : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x000068 : "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x000069 : "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x00006A : "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x00006B : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x00006C : "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x00006D : "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x000084 : "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x000085 : "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x000086 : "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x000087 : "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x000088 : "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x000089 : "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x00008A : "TLS_PSK_WITH_RC4_128_SHA",
	0x00008B : "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
	0x00008C : "TLS_PSK_WITH_AES_128_CBC_SHA",
	0x00008D : "TLS_PSK_WITH_AES_256_CBC_SHA",
	0x00008E : "TLS_DHE_PSK_WITH_RC4_128_SHA",
	0x00008F : "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
	0x000090 : "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
	0x000091 : "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
	0x000092 : "TLS_RSA_PSK_WITH_RC4_128_SHA",
	0x000093 : "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
	0x000094 : "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
	0x000095 : "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
	0x000096 : "TLS_RSA_WITH_SEED_CBC_SHA",
	0x000097 : "TLS_DH_DSS_WITH_SEED_CBC_SHA",
	0x000098 : "TLS_DH_RSA_WITH_SEED_CBC_SHA",
	0x000099 : "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
	0x00009A : "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	0x00009B : "TLS_DH_anon_WITH_SEED_CBC_SHA",
	0x00009C : "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x00009D : "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x00009E : "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x00009F : "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x0000A0 : "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	0x0000A1 : "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	0x0000A2 : "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x0000A3 : "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x0000A4 : "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	0x0000A5 : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	0x0000A6 : "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x0000A7 : "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0x0000A8 : "TLS_PSK_WITH_AES_128_GCM_SHA256",
	0x0000A9 : "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0x0000AA : "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
	0x0000AB : "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	0x0000AC : "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
	0x0000AD : "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
	0x0000AE : "TLS_PSK_WITH_AES_128_CBC_SHA256",
	0x0000AF : "TLS_PSK_WITH_AES_256_CBC_SHA384",
	0x0000B0 : "TLS_PSK_WITH_NULL_SHA256",
	0x0000B1 : "TLS_PSK_WITH_NULL_SHA384",
	0x0000B2 : "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
	0x0000B3 : "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
	0x0000B4 : "TLS_DHE_PSK_WITH_NULL_SHA256",
	0x0000B5 : "TLS_DHE_PSK_WITH_NULL_SHA384",
	0x0000B6 : "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
	0x0000B7 : "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
	0x0000B8 : "TLS_RSA_PSK_WITH_NULL_SHA256",
	0x0000B9 : "TLS_RSA_PSK_WITH_NULL_SHA384",
	0x0000BA : "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x0000BB : "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	0x0000BC : "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x0000BD : "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	0x0000BE : "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x0000BF : "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
	0x0000C0 : "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x0000C1 : "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	0x0000C2 : "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x0000C3 : "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	0x0000C4 : "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x0000C5 : "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
	0x0000FF : "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x00c001 : "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0x00c002 : "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0x00c003 : "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0x00c004 : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0x00c005 : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0x00c006 : "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0x00c007 : "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0x00c008 : "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0x00c009 : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0x00c00a : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0x00c00b : "TLS_ECDH_RSA_WITH_NULL_SHA",
	0x00c00c : "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0x00c00d : "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x00c00e : "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0x00c00f : "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0x00c010 : "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0x00c011 : "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0x00c012 : "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x00c013 : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0x00c014 : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0x00c015 : "TLS_ECDH_anon_WITH_NULL_SHA",
	0x00c016 : "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0x00c017 : "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0x00c018 : "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0x00c019 : "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0x00C01A : "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
	0x00C01B : "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
	0x00C01C : "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
	0x00C01D : "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
	0x00C01E : "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
	0x00C01F : "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
	0x00C020 : "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
	0x00C021 : "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
	0x00C022 : "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
	0x00C023 : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0x00C024 : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0x00C025 : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0x00C026 : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0x00C027 : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0x00C028 : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0x00C029 : "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0x00C02A : "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0x00C02B : "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0x00C02C : "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0x00C02D : "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0x00C02E : "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0x00C02F : "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0x00C030 : "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00C031 : "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0x00C032 : "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0x00C033 : "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
	0x00C034 : "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
	0x00C035 : "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	0x00C036 : "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0x00C037 : "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
	0x00C038 : "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	0x00C039 : "TLS_ECDHE_PSK_WITH_NULL_SHA",
	0x00C03A : "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	0x00C03B : "TLS_ECDHE_PSK_WITH_NULL_SHA384",
	0x00CC13 : "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x00CC14 : "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0x00CC15 : "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x00E410 : "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1",
	0x00E411 : "TLS_RSA_WITH_SALSA20_SHA1",
	0x00E412 : "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1",
	0x00E413 : "TLS_ECDHE_RSA_WITH_SALSA20_SHA1",
	0x00E414 : "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1",
	0x00E415 : "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1",
	0x00E416 : "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1",
	0x00E417 : "TLS_PSK_WITH_SALSA20_SHA1",
	0x00E418 : "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1",
	0x00E419 : "TLS_ECDHE_PSK_WITH_SALSA20_SHA1",
	0x00E41A : "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1",
	0x00E41B : "TLS_RSA_PSK_WITH_SALSA20_SHA1",
	0x00E41C : "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1",
	0x00E41D : "TLS_DHE_PSK_WITH_SALSA20_SHA1",
	0x00E41E : "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1",
	0x00E41F : "TLS_DHE_RSA_WITH_SALSA20_SHA1",
	0x00fefe : "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
	0x00feff : "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
	0x00ffe0 : "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
	0x00ffe1 : "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
	0x010080 : "SSL2_RC4_128_WITH_MD5",
	0x020080 : "SSL2_RC4_128_EXPORT40_WITH_MD5",
	0x030080 : "SSL2_RC2_CBC_128_CBC_WITH_MD5",
	0x040080 : "SSL2_RC2_CBC_128_CBC_WITH_MD5",
	0x050080 : "SSL2_IDEA_128_CBC_WITH_MD5",
	0x060040 : "SSL2_DES_64_CBC_WITH_MD5",
	0x0700c0 : "SSL2_DES_192_EDE3_CBC_WITH_MD5",
	0x080080 : "SSL2_RC4_64_WITH_MD5",
	0x800001 : "PCT_SSL_CERT_TYPE | PCT1_CERT_X509",
	0x800003 : "PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN",
	0x810001 : "PCT_SSL_HASH_TYPE | PCT1_HASH_MD5",
	0x810003 : "PCT_SSL_HASH_TYPE | PCT1_HASH_SHA",
	0x820001 : "PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1",
	0x830004 : "PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4",
	0x842840 : "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128",
	0x848040 : "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128",
	0x8f8001 : "PCT_SSL_COMPAT | PCT_VERSION_1",
}

SSL_CompressionMethod = {
	0x00 : "Null",
}

class CipherSuite(Packet):
	name = "CipherSuite "
	fields_desc=[
		ShortEnumField("CSValue", 0x0016, SSL_ciphersuite),
	]
	def extract_padding(self, p):
		return "", p

class CompressionMethod(Packet):
	name = "CompressionMethod "
	fields_desc=[
		ByteEnumField("Method", 0x0, SSL_CompressionMethod),
	]
	def extract_padding(self, p):
		return "", p

class SSLClientHello(Packet):
	name = "SSLClientHello "
	fields_desc=[
		IntField("UnixTime", 0x3f47d7f7),
        StrFixedLenField("RandomeBytes", "\x00"*28, 28),
        FieldLenField("SessionIDLen", None, count_of="SessionID", fmt="B"),
		ConditionalField(StrLenField("SessionID", "\xAA\xAA", length_from = lambda pkt: pkt.SessionIDLen),
                        lambda pkt:pkt.SessionIDLen < 0),
		FieldLenField("CiphersuitesLen", None, count_of="CipherSuites"),
		PacketListField("CipherSuites", None, CipherSuite, length_from=lambda pkt:pkt.CiphersuitesLen),
		FieldLenField("CompressionMethodsLen", None, count_of="CompressionMethods", fmt="B"),
		PacketListField("CompressionMethods", None, CompressionMethod, length_from=lambda pkt:pkt.CompressionMethodsLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLServerHello(Packet):
	name = "SSLServerHello "
	fields_desc=[
		IntField("UnixTime", 0x3f47d7f7),
		StrFixedLenField("RandomeBytes", "\x00"*28, 28),
		FieldLenField("SessionIDLen", None, count_of="SessionID", fmt="B"),
		StrLenField("SessionID", "\xAA\xAA", length_from = lambda pkt: pkt.SessionIDLen),
		ShortEnumField("CipherSuite", 0x0016, SSL_ciphersuite),
		FieldLenField("CompressionMethodsLen", None, count_of="CompressionMethods", fmt="B"),
		PacketListField("CompressionMethods", None, CompressionMethod, length_from=lambda pkt:pkt.CompressionMethodsLen),
	]
	def extract_padding(self, p):
		return "", p

SSL_Extensions = {
	0x0000 : "'server_name'",
	0x000a : "'elliptic_curves'",
	0x000b : "'ec_point_formats'",
	0x000d : "'signature_algorithms'",
	0x000f : "'Heartbeat'",
	0x0015 : "'Padding'",
	0x0023 : "'SessionTicket TLS'",
}

SSL_SNTypes = {
	0x00 : "'host_name'",
}

class SSLServerName(Packet):
	name = "SSLServerName "
	fields_desc=[
		ShortField("ELen", 16),
		ShortField("list_len", 14),
		ByteEnumField("SNType", 0, SSL_SNTypes),
		FieldLenField("SNLen", None, count_of="SNValue"),
		StrLenField("SNValue", "google.com", length_from=lambda pkt:pkt.SNLen),
	]
	def extract_padding(self, p):
		return "", p


pointformats = {
	0x00 : "'uncompressed'",
	0x01 : "'ansiX962_compressed_prime'",
	0x02 : "'ansiX962_compressed_char2'",
}

class ECpointformat(Packet):
	name = "ECpointformat "
	fields_desc=[
		ByteEnumField("format", 0, pointformats),
	]
	def extract_padding(self, p):
		return "", p

class SSLECurveFormat(Packet):
	name = "SSLECurveFormat "
	fields_desc=[
		ShortField("ELen", 16),
		FieldLenField("formatLen", None, count_of="ECpointformats", fmt="B"),
		PacketListField("ECpointformats", None, ECpointformat, length_from=lambda pkt:pkt.formatLen),		
	]
	def extract_padding(self, p):
		return "", p

ellyptic_curves = {
	0x0009 : "'sect283k1'",
	0x000a : "'sect283r1'",
	0x000b : "'sect409k1'",
	0x000c : "'sect409r1'",
	0x000d : "'sect571k1'",
	0x000e : "'sect571r1'",
	0x0016 : "'secp256k1'",
	0x0017 : "'secp256r1'",
	0x0018 : "'secp384r1'",
	0x0019 : "'secp521r1'",
	0x001a : "'brainpoolP256r1'",
	0x001b : "'brainpoolP384r1'",
	0x001c : "'brainpoolP512r1'",
}

class EllypticCurve(Packet):
	name = "EllypticCurve "
	fields_desc=[
		ShortEnumField("curve", 0, ellyptic_curves),
	]
	def extract_padding(self, p):
		return "", p

class SSLECurves(Packet):
	name = "SSLECurves "
	fields_desc=[
		ShortField("ELen", 16),
		FieldLenField("CurvesLen", None, count_of="ECpointformats"),
		PacketListField("EllypticCurves", None, EllypticCurve, length_from=lambda pkt:pkt.CurvesLen),
	]
	def extract_padding(self, p):
		return "", p

class SessionTicketsTLS(Packet):
	name = "SessionTicketsTLS "
	fields_desc=[
		FieldLenField("ELen", None, count_of="TicketData"),
		StrLenField("TicketData", None, length_from=lambda pkt:pkt.ELen),
	]
	def extract_padding(self, p):
		return "", p

hash_algorithms = {
	0x02 : "'SHA1'",
	0x03 : "'SHA224'",
	0x04 : "'SHA256'",
	0x05 : "'SHA384'",
	0x06 : "'SHA512'",
}

algorithm_signatures = {
	0x01 : "'RSA'",
	0x02 : "'DSA'",
	0x03 : "'ECDSA'",
}

class HashAlgorithm(Packet):
	name = "HashAlgorithm "
	fields_desc=[
		ByteEnumField("SHAHash", 0x06, hash_algorithms),
		ByteEnumField("HashAlgorithm", 0x01, algorithm_signatures),
	]
	def extract_padding(self, p):
		return "", p

class SSLSignatureAlgorithm(Packet):
	name = "SSLSignatureAlgorithm "
	fields_desc=[
		ShortField("ELen", 32),
		FieldLenField("HashLen", None, count_of="SignatureHashes"),
		PacketListField("SignatureHashes", None, HashAlgorithm, length_from=lambda pkt:pkt.HashLen),
	]
	def extract_padding(self, p):
		return "", p

heartbeat_mode = {
	0x01 : "'Peer allowed to send requests'",
}

class SSLHeartBeat(Packet):
	name = "SSLHeartBeat "
	fields_desc=[
		ShortField("ELen", 0x0001),
		ByteEnumField("Mode", 0x01, heartbeat_mode),
	]
	def extract_padding(self, p):
		return "", p

class SSLPadding(Packet):
	name = "SSLPadding "
	fields_desc=[
		FieldLenField("PaddingLen", None, count_of="PaddingData"),
		StrLenField("PaddingData", None, length_from=lambda pkt:pkt.PaddingLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLExtensions(Packet):
	name = "SSLExtensions " 
	fields_desc=[
		ShortEnumField("EType", 0, SSL_Extensions),
		ConditionalField(PacketField("ServerNameExt", None, SSLServerName),
                        lambda pkt:pkt.EType == 0x0000),
		ConditionalField(PacketField("EllypticCurveFormat", None, SSLECurveFormat),
                        lambda pkt:pkt.EType == 0x000b),
		ConditionalField(PacketField("EllypticCurvesList", None, SSLECurves),
                        lambda pkt:pkt.EType == 0x000a),
		ConditionalField(PacketField("SessionTickets", None, SessionTicketsTLS),
                        lambda pkt:pkt.EType == 0x0023),
		ConditionalField(PacketField("SignatureAlgorithms", None, SSLSignatureAlgorithm),
                        lambda pkt:pkt.EType == 0x000d),
		ConditionalField(PacketField("HeartBeatExt", None, SSLHeartBeat),
                        lambda pkt:pkt.EType == 0x000f),
		ConditionalField(PacketField("Padding", None, SSLPadding),
                        lambda pkt:pkt.EType == 0x0015),
	]
	def extract_padding(self, p):
		return "", p

class SSLCertificates(Packet):
	name = "SSLCertificates "
	fields_desc=[
		X3BytesField("CertLen", None),
		StrLenField("Certificate", None, length_from=lambda pkt:pkt.CertLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLServerKeyExchange(Packet):
	name = "SSLServerKeyExchange "
	fields_desc=[
		FieldLenField("DHp_Len", None, count_of="DHp"),
		StrLenField("DHp", None, length_from=lambda pkt:pkt.DHp_Len),
		FieldLenField("DHg_Len", None, count_of="DHg"),
		StrLenField("DHg", None, length_from=lambda pkt:pkt.DHg_Len),
		FieldLenField("PubkeyLen", None, count_of="Pubkey"),
		StrLenField("Pubkey", None, length_from=lambda pkt:pkt.PubkeyLen),
		FieldLenField("SignatureLen", None, count_of="Signature"),
		StrLenField("Signature", None, length_from=lambda pkt:pkt.SignatureLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLRSAEncryptedPreMasterSecret(Packet):
	name = "SSLServerKeyExchange "
	fields_desc=[
		FieldLenField("EncryptedPreMasterSecretLen", None, count_of="EncryptedPreMasterSecret"),
		StrLenField("EncryptedPreMasterSecret", None, length_from=lambda pkt:pkt.EncryptedPreMasterSecretLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLTLSSessionTicket(Packet):
	name = "SSLTLSSessionTicket "
	fields_desc=[
		IntField("SessionTicketLifeTimeHint", 300),
		FieldLenField("SessionTicketLen", 0x00d0, count_of="SessionTicket"),
		StrLenField("SessionTicket", None, length_from=lambda pkt:pkt.SessionTicketLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLHandshake(Packet):
	name = "SSLHandshake "
	fields_desc=[
		ByteEnumField("HandshakeType", 0x16, SSLHandshakeType),
		X3BytesField("HSLength", 0),
		ConditionalField(ShortEnumField("HSVersion", 0x0300, SSLVersion),
						lambda pkt:(pkt.HandshakeType == 0x01 or pkt.HandshakeType == 0x02)),
		ConditionalField(PacketField("protoHello", None, SSLClientHello),
                        lambda pkt:pkt.HandshakeType == 0x01),
		ConditionalField(PacketField("protoHello", None, SSLServerHello),
                        lambda pkt:pkt.HandshakeType == 0x02),
		ConditionalField(FieldLenField("ExtensionsLen", None, count_of="Extensions"),
						lambda pkt:pkt.HandshakeType == 0x01),
		ConditionalField(PacketListField("Extensions", None, SSLExtensions, length_from=lambda pkt:pkt.ExtensionsLen),
						lambda pkt:pkt.HandshakeType == 0x01),
		ConditionalField(X3BytesField("CertificateLen", None),
                        lambda pkt:pkt.HandshakeType == 0x0b),
		ConditionalField(PacketListField("Certificates", None, SSLCertificates, length_from=lambda pkt:pkt.CertificateLen),
                        lambda pkt:pkt.HandshakeType == 0x0b),
		ConditionalField(PacketField("ServerKeyExchange", None, SSLServerKeyExchange),
                        lambda pkt:pkt.HandshakeType == 0x0c),
		ConditionalField(PacketField("RSAEncPMSecret", None, SSLRSAEncryptedPreMasterSecret),
                        lambda pkt:pkt.HandshakeType == 0x10),
		ConditionalField(PacketField("SessionTickets", None, SSLTLSSessionTicket),
                        lambda pkt:pkt.HandshakeType == 0x04),
	]
	def extract_padding(self, p):
		return "", p

class SSLEncryptedHSMessage(Packet):
	name = "SSLEncryptedHSMessage "
	fields_desc=[
		ByteEnumField("ContentType2", 0x16, SSLContentType),
		ShortEnumField("Version2", 0x0300, SSLVersion),
		FieldLenField("EncryptedHSMessageLen", None, count_of="EncryptedHSMessage"),
		StrLenField("EncryptedHSMessage", None, length_from=lambda pkt:pkt.EncryptedHSMessageLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLApplicationData(Packet):
	name = "SSLApplicationData "
	fields_desc=[
		FieldLenField("ADLen", None, count_of="AData"),
		StrLenField("AData", None, length_from=lambda pkt:pkt.ADLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLEncryptionAlert(Packet):
	name = "SSLEncryptionAlert "
	fields_desc=[
		FieldLenField("EncAlertLen", None, count_of="AlertMessage"),
		StrLenField("AlertMessage", None, length_from=lambda pkt:pkt.EncAlertLen),
	]
	def extract_padding(self, p):
		return "", p

class SSLRecord(Packet):
	name = "SSLRecord "
	fields_desc=[ 
		ByteEnumField("ContentType", 0x16, SSLContentType),
		ShortEnumField("Version", 0x0300, SSLVersion),
		ConditionalField(FieldLenField("Length", None, count_of="SSLHandshakes"),
						 lambda pkt:pkt.ContentType == 0x16),
		ConditionalField(PacketListField("SSLHandshakes", None, SSLHandshake, length_from=lambda pkt:pkt.Length),
						lambda pkt:pkt.ContentType == 0x16),
		ConditionalField(FieldLenField("ChangeCipherSpecLen", None, count_of="ChangeCipherSpec"),
                         lambda pkt:pkt.ContentType == 0x14),
		ConditionalField(StrLenField("ChangeCipherSpec", None, length_from=lambda pkt:pkt.ChangeCipherSpecLen),
                        lambda pkt:pkt.ContentType == 0x14),
		ConditionalField(PacketField("HandShakeMessage", None, SSLEncryptedHSMessage),
                        lambda pkt:pkt.ContentType == 0x14),
		ConditionalField(PacketField("ApplicationData", None, SSLApplicationData),
                        lambda pkt:pkt.ContentType == 0x17),
		ConditionalField(PacketField("Alert", None, SSLEncryptionAlert),
                        lambda pkt:pkt.ContentType == 0x15),
	]
