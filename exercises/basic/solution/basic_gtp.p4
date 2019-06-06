/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

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
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<16>  udpLen;
    bit<16>  udpChecksum;
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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4_outer;
    udp_t        udp_outer;
    gtp_t        gtp;
    ipv4_t       ipv4_inner;
    udp_t        udp_inner;
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
	    0x800: parse_ipv4_outer;
	    default: accept;
	}
    }

    state parse_ipv4_outer {
	packet.extract(hdr.ipv4_outer);
	transition select(hdr.ipv4_outer.protocol) {
	    0x11: parse_udp_outer;
	    default: accept;
	}
    }

    state parse_udp_outer {
	packet.extract(hdr.udp_outer);
	transition select(hdr.udp_outer.dstPort) {
	    0x0868: parse_gtp;
	    default: accept;
	}
    }

    state parse_gtp {
	packet.extract(hdr.gtp);
	transition parse_ipv4_inner;
    }

    state parse_ipv4_inner {
	packet.extract(hdr.ipv4_inner);
	transition select(hdr.ipv4_inner.protocol) {
	    0x11: parse_udp_inner;
	    default: accept;
	}
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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4_outer.ttl = hdr.ipv4_outer.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4_outer.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action gtp_forward(ip4Addr_t dst_ip, macAddr_t dstAddr, egressSpec_t port) {
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4_outer.dstAddr = dst_ip;
	hdr.ipv4_outer.ttl = hdr.ipv4_outer.ttl - 1;
	hdr.ipv4_inner.ttl = hdr.ipv4_inner.ttl - 1;
    }

    table gtp_exact {
	key = {
	    hdr.ipv4_inner.srcAddr: exact;
	}
	actions = {
	    gtp_forward;
	    drop;
	}
	size = 1024;
	default_action = drop();
    }
    
    apply {
	if (hdr.ipv4_outer.isValid() && !hdr.gtp.isValid()) {
	    ipv4_lpm.apply();
	}
	
	if (hdr.gtp.isValid()) {
	    gtp_exact.apply();
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

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4_outer.isValid(),
            { hdr.ipv4_outer.version,
	      hdr.ipv4_outer.ihl,
              hdr.ipv4_outer.diffserv,
              hdr.ipv4_outer.totalLen,
              hdr.ipv4_outer.identification,
              hdr.ipv4_outer.flags,
              hdr.ipv4_outer.fragOffset,
              hdr.ipv4_outer.ttl,
              hdr.ipv4_outer.protocol,
              hdr.ipv4_outer.srcAddr,
              hdr.ipv4_outer.dstAddr },
            hdr.ipv4_outer.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4_outer);
	packet.emit(hdr.udp_outer);
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