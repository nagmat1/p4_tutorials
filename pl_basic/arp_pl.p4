/* -*- P4_17 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> UDP_PROTOCOL = 0x11;
const bit<8> TCP_PROTOCOL = 0x06;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IPPROTO_ICMP   = 0x01;

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

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    macAddr_t  sha;
    ip4Addr_t spa;
    macAddr_t  tha;
    ip4Addr_t tpa;
}

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


struct metadata {
    ip4Addr_t dst_ipv4;
    macAddr_t  mac_da;
    macAddr_t  mac_sa;
    egressSpec_t egress_port;
    macAddr_t  my_mac;

    /* empty */
}

header metadata_t {
    bit<32> enq_timestamp;
    bit<32> enq_qdepth;
    bit<32> deq_timedelta;
    bit<32> deq_qdepth;
}


struct headers {
    ethernet_t   ethernet;
    arp_t         arp;
    arp_ipv4_t    arp_ipv4;
    ipv4_t       ipv4;
    udp_t        udp;
    tcp_t        tcp;
    icmp_t        icmp;
    metadata_t   my_meta;
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
            ETHERTYPE_ARP  : parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
        UDP_PROTOCOL: parse_udp;
        TCP_PROTOCOL: parse_tcp;
        IPPROTO_ICMP : parse_icmp;
        default : accept;
    }

}

state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }


 state parse_udp{
         packet.extract(hdr.udp);
         transition accept;
    }

 state parse_tcp{
         packet.extract(hdr.tcp);
         transition accept;
    }

state parse_icmp {
        packet.extract(hdr.icmp);
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

    action ipv4_forward(egressSpec_t port) {
        //standard_metadata.egress_spec = port;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //hdr.ethernet.dstAddr = dstAddr;
        meta.egress_port = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action forward_ipv4() {
        //hdr.ethernet.dstAddr = meta.mac_da;
        //hdr.ethernet.srcAddr = meta.mac_sa;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;

        standard_metadata.egress_spec = meta.egress_port;
    }

    action send_arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = meta.mac_da;

        hdr.arp.oper         = ARP_OPER_REPLY;

        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = meta.mac_da;
        hdr.arp_ipv4.spa     = meta.dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

  action send_icmp_reply() {
        macAddr_t   tmp_mac;
        ip4Addr_t  tmp_ip;

        tmp_mac              = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;

        tmp_ip               = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr     = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr     = tmp_ip;

        hdr.icmp.type        = ICMP_ECHO_REPLY;
        hdr.icmp.checksum    = 0; // For now

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table forward {
        key = {
            hdr.arp.isValid()      : exact;
            hdr.arp.oper           : ternary;
            hdr.arp_ipv4.isValid() : exact;
            hdr.ipv4.isValid()     : exact;
            hdr.icmp.isValid()     : exact;
            hdr.icmp.type          : ternary;
        }
        actions = {
            forward_ipv4;
            send_arp_reply;
            send_icmp_reply;
            NoAction;
        }
        const default_action = NoAction();
        const entries = {
            ( true, ARP_OPER_REQUEST, true, false, false, _  ) :
                                                         send_arp_reply();
            ( false, _,               false, true, false, _  ) :
                                                         forward_ipv4();
            ( false, _,               false, true, true, ICMP_ECHO_REQUEST ) :
                                                         send_icmp_reply();
        }
    }

    apply {
        ipv4_lpm.apply();
        forward.apply();
        //if (hdr.arp.isValid()) { send_arp_reply;}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

struct my_egress_metadata{
    bit<48> enq_timestamp;
    bit<19> enq_depth;
    bit<32> deq_time_delta;
    bit<19> deq_depth;
    bit<8> qid;

}
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
           hdr.my_meta.setValid();
           hdr.my_meta.enq_timestamp = 0xA; //standard_metadata.enq_timestamp;
           hdr.my_meta.enq_qdepth = (bit<32>) 0xB; //standard_metadata.enq_qdepth;
           hdr.my_meta.deq_timedelta = 0xC; //standard_metadata.deq_timedelta;
           hdr.my_meta.deq_qdepth = (bit<32>) 0xD; //standard_metadata.deq_qdepth;
 }
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
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.my_meta);
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
