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

    Register<bit<32>, _>(1) sequence;
    RegisterAction<bit<32>, _, bit<32>>(sequence) assign_sequence = {
        void apply(inout bit<32> reg, out bit<32> result) {
            reg = reg + 1;
            result = reg;
        }
    };
 
    action set_meta(bit<16> port) {
        hdr.udp.checksum = 0;
        hdr.udp.dst_port = port;
        hdr.neo.sequence = assign_sequence.execute(0);
        // TODO signature
        // bit<8> padding = (bit<8>)hdr.neo.sequence;
        // hdr.neo.signature[7:0] = padding;
        // hdr.neo.signature[23:16] = padding;
        hdr.neo.hash = 0;
    }

    table dmac {
        key = { hdr.ethernet.dst_addr : exact; }
        actions = { send; }
    }

    // keyless tables that always perform default action, need to be configured
    // by control plane

    table send_to_replicas {
        actions = { send_to_group; }
    }

    table send_to_endpoints {
        actions = { send_to_group; }
    }

    table do_set_meta {
        actions = { set_meta; }
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
        
        /* if (hdr.neo.sequence == 0xffffffff) {
            sequence.write(0, 0);
            drop();
            exit;
        } */

        do_set_meta.apply();
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
