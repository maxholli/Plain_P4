/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   udpLength;
    bit<16>   udpChecksum;
}

header gtp_t {
    bit<3>   version;
    bit<1>   p_type;
    bit<1>   reserved;
    bit<1>   ext_flag;
    bit<1>   seq_flag;
    bit<1>   n_pdu_flag;
    bit<8>   message_type;
    bit<16>  message_length;
    bit<32>  teid;
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
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    gtp_t        gtp;
    ipv4_t       ipv4_inner;
    udp_t        udp_inner;
    arp_t        arp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
	    0x806: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
	    0x11: parse_udp;
	    default: accept;
	}
    }

    state parse_arp {
	packet.extract(hdr.arp);
	transition accept;
    }
    
    state parse_ipv4_inner {
        packet.extract(hdr.ipv4_inner);
        transition select(hdr.ipv4_inner.protocol) {
	    0x11: parse_udp_inner;
	    default: accept;
	}
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
	    0x0868: parse_gtp;
	    default: accept;
	}
    }

    state parse_gtp {
	packet.extract(hdr.gtp);
	transition parse_ipv4_inner;
    }

    state parse_udp_inner {
        packet.extract(hdr.udp_inner);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    /*
    action eth_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }
    
    table eth_lpm {
        key = {
            hdr.eth.dstAddr: lpm;
        }
        actions = {
            eth_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    action udp_forward(macAddr_t dstAddr, egressSpec_t port) {
	standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	hdr.udp.dstPort = 1234;
    }

    table udp_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            udp_forward;
	    drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action udp_reroute(macAddr_t dstAddr, egressSpec_t port, ip4Addr_t ipdst) {
	standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.dstAddr = ipdst;
    }

    action set_arp_out(bit<9> port) {
	standard_metadata.egress_spec = port;
    }

    table udp_reroute_lpm {
        key = {
            hdr.ipv4_inner.srcAddr: lpm;
        }
        actions = {
            udp_reroute;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table arp_out {
	actions = {
	    set_arp_out;
	    drop;
	    NoAction;
	}
	key = {
	    hdr.arp.protoDstAddr: exact;
	}
	size = 1024;
	default_action = NoAction();
    }
    
    apply {
	if (hdr.arp.isValid() && !hdr.ipv4.isValid()) {
	    arp_out.apply();

	}
        if (hdr.ipv4.isValid() && !hdr.udp.isValid()) {
            // Process only non-tunneled IPv4 packets
            ipv4_lpm.apply();
        }

        if (hdr.udp.isValid()) {
            // process tunneled packets
            udp_lpm.apply();
	    udp_reroute_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.udp);
	packet.emit(hdr.gtp);
	packet.emit(hdr.ipv4_inner);
	packet.emit(hdr.udp_inner);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
