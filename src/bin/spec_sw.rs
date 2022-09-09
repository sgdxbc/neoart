use std::fs::{read_to_string, write};

use neoart::{
    bin::Spec,
    meta::{MULTICAST_CONTROL_RESET_PORT, MULTICAST_PORT},
};

fn main() {
    let spec = toml::from_str::<Spec>(&read_to_string("spec.toml").unwrap()).unwrap();
    write("src-sw/neo_s.py", rewrite_sw(spec.clone(), false)).unwrap();
    write("src-sw/neo_s-sim.py", rewrite_sw(spec.clone(), true)).unwrap();
}

fn rewrite_sw(spec: Spec, simulate: bool) -> String {
    let mut dmac = Vec::new();
    let mut port = Vec::new();
    let mut replicas = Vec::new();
    let mut endpoints = Vec::new();
    for mut node in spec.replica {
        if node.link_speed.is_empty() {
            node.link_speed = String::from("100G");
        }
        dmac.push((node.link, node.dev_port));
        port.push((node.dev_port, node.link_speed));
        replicas.push(node.dev_port);
        endpoints.push(node.dev_port);
    }
    for mut node in spec.client {
        if node.link_speed.is_empty() {
            node.link_speed = String::from("100G");
        }
        dmac.push((node.link, node.dev_port));
        port.push((node.dev_port, node.link_speed));
        endpoints.push(node.dev_port);
    }
    const ENDPOINT_GROUP: u16 = 1;
    const REPLICA_GROUP: u16 = 2;
    const ENDPOINT_NODE: u16 = 1;
    const REPLICA_NODE: u16 = 2;
    let pre_node = [(ENDPOINT_NODE, endpoints), (REPLICA_NODE, replicas)]
        .into_iter()
        .map(|(group_id, ports)| (group_id, 0xffff, ports))
        .collect::<Vec<_>>();
    let pre_mgid = [
        (ENDPOINT_GROUP, vec![ENDPOINT_NODE]),
        (REPLICA_GROUP, vec![REPLICA_NODE]),
    ];

    let sw = include_str!("spec_sw.in.py");
    sw.replace(r#""@@PROGRAM@@""#, "bfrt.neo_s")
        .replace(r#""@@SIMULATE@@""#, if simulate { "True" } else { "False" })
        .replace(r#""@@MULTICAST_PORT@@""#, &MULTICAST_PORT.to_string())
        .replace(
            r#""@@MULTICAST_CONTROL_RESET_PORT@@""#,
            &MULTICAST_CONTROL_RESET_PORT.to_string(),
        )
        .replace(r#""@@DMAC@@""#, &format!("{dmac:?}"))
        .replace(r#""@@PORT@@""#, &format!("{port:?}"))
        .replace(r#""@@ENDPOINT_GROUP@@""#, &ENDPOINT_GROUP.to_string())
        .replace(r#""@@REPLICA_GROUP@@""#, &REPLICA_GROUP.to_string())
        .replace(r#""@@PRE_NODE@@""#, &format!("{pre_node:?}"))
        .replace(r#""@@PRE_MGID@@""#, &format!("{pre_mgid:?}"))
}
