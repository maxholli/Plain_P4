/* -*- P4_16 -*- */

#ifndef __HEADER_P4__
#define __HEADER_P4__ 1

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16>  hwType;
    bit<16>  protoType;
    bit<8>   hwAddrLen;
    bit<8>   protoAddrLen;
    bit<16>  opcode;
    bit<48>  hwSrcAddr;
    bit<32>  protoSrcAddr;
    bit<48>  hwDstAddr;
    bit<32>  protoDstAddr;
}



struct metadata {
    @name("ingress_metadata")
    ingress_metadata_t   ingress_metadata;
}

struct headers {
    @name("ethernet")
    ethernet_t ethernet;
    @name("ipv4")
    ipv4_t     ipv4;
    @name("arp")	
    arp_t      arp;
}

#endif // __HEADER_P4__
