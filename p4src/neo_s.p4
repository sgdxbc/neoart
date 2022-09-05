// NeoBFT switch program, signing mode
#include "common.p4"

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action send_to_group(MulticastGroupId_t mgid) {
        ig_tm_md.mcast_grp_a = mgid;
        ig_tm_md.rid = 0xffff;
    }

    table dmac {
        key = { hdr.ethernet.dst_addr : exact; }
        actions = { send; }
        size = 8;
    }

    // keyless tables that always perform default action, need to be configured
    // by control plane

    table send_to_replicas {
        actions = { send_to_group; }
        size = 1;
    }

    table send_to_endpoints {
        actions = { send_to_group; }
        size = 1;
    }

    bit<32> code;
    bit<32> sequence_number;

    Register<bit<32>, _>(1, 0) sequence;
    RegisterAction<bit<32>, _, bit<32>>(sequence) assign_sequence = {
        void apply(inout bit<32> reg, out bit<32> result) {
            if (code == 0) {
                reg = reg + 1;
            } else {
                reg = 0;
            }
            result = reg;
        }
    };

    action neo_multicast(bit<16> port) {
        hdr.udp.checksum = 0;
        hdr.udp.dst_port = port;
        hdr.neo.sequence = sequence_number;
        // TODO signature
        bit<8> n1 = (bit<8>)hdr.neo.sequence;
        bit<8> n2 = (bit<8>)hdr.neo.sequence + 1;
        hdr.neo.signature[7:0] = n1;
        hdr.neo.signature[15:8] = n2;
        hdr.neo.hash = 0;
    }

    table neo {
        actions = { neo_multicast; }
        size = 1;
    }

    apply {
        // No need for egress processing, skip it and use empty controls for egress.
        ig_tm_md.bypass_egress = 1w1;
 
        if (!hdr.neo.isValid()) {
            if (hdr.ethernet.ether_type == ETHERTYPE_ARP) {
                send_to_endpoints.apply(); // a little bit wild here
            } else if (hdr.ipv4.protocol == IP_PROTOCOLS_UDP) {
                dmac.apply();
            } else {
                drop();
            }
            exit;
        }
        
        code = hdr.neo.sequence;
        sequence_number = assign_sequence.execute(0);
        if (code != 0) {
            drop();
            exit;
        }
        neo.apply();
        send_to_replicas.apply();
    }
}

Pipeline(
        SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        EmptyEgressParser(),
        EmptyEgress(),
        EmptyEgressDeparser()) pipe;

Switch(pipe) main;
