// NeoBFT switch program, relay mode
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
    }

    // keyless tables that always perform default action, need to be configured
    // by control plane

    table send_to_accel {
        actions = { send; }
    }

    table send_to_replicas {
        actions = { send_to_group; }
    }

    table send_to_endpoints {
        actions = { send_to_group; }
    }

    apply {
        hdr.neo.variant = NEO_VARIANT_R;
        
        if (!hdr.neo.isValid() || hdr.neo.ty == NEO_TYPE_UCAST) {
            if (dmac.apply().miss) {
                send_to_endpoints.apply();
            }
        } else if (hdr.neo.ty == NEO_TYPE_MCAST_RELAY) {
            hdr.neo.ty = NEO_TYPE_MCAST_OUTGRESS;
            send_to_replicas.apply();
        } else if (hdr.neo.ty == NEO_TYPE_MCAST_INGRESS) {
            hdr.neo.ty = NEO_TYPE_MCAST_RELAY;
            send_to_accel.apply();
        } else {
            // unreachable
            drop();
        }

        // No need for egress processing, skip it and use empty controls for egress.
        ig_tm_md.bypass_egress = 1w1;
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
