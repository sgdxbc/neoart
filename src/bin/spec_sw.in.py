SIMULATE = "@@SIMULATE@@"
PROGRAM = "@@PROGRAM@@"
MULTICAST_PORT = "@@MULTICAST_PORT@@"
MULTICAST_CONTROL_RESET_PORT = "@@MULTICAST_CONTROL_RESET_PORT@@"
DMAC = "@@DMAC@@"
PORT = "@@PORT@@"
PRE_MGID = "@@PRE_MGID@@"
PRE_NODE = "@@PRE_NODE@@"
GROUP_ENDPOINT = "@@GROUP_ENDPOINT@@"
GROUP_REPLICA = "@@GROUP_REPLICA@@"

if 0: # small hack to suppress IDE warning
    bfrt = ...

if not SIMULATE:
    bfrt.port.port.clear()
    for dev_port, speed in PORT:
        bfrt.port.port.add(
            DEV_PORT=dev_port,
            SPEED="BF_SPEED_" + speed,
            FEC="BF_FEC_TYP_NONE",
            PORT_ENABLE=True,
            AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE",
        )

for entry in PROGRAM.pipe.SwitchIngress.info(True, False):
    if entry["type"] != "MATCH_DIRECT":
        continue
    entry["node"].clear()
    entry["node"].reset_default()
for entry in bfrt.pre.node.dump(return_ents=True) or []:
    entry.remove()
for entry in bfrt.pre.mgid.dump(return_ents=True) or []:
    entry.remove()
PROGRAM.pipe.SwitchIngressParser.neo_port.clear()

for dst_addr, port in DMAC:
    PROGRAM.pipe.SwitchIngress.dmac.add_with_send(dst_addr=dst_addr, port=port)

for node_id, rid, ports in PRE_NODE:
    bfrt.pre.node.add(node_id, rid, [], ports)
for group_id, nodes in PRE_MGID:
    bfrt.pre.mgid.add(group_id, nodes, [0] * len(nodes), [0] * len(nodes))
PROGRAM.pipe.SwitchIngress.send_to_endpoints.set_default_with_send_to_group(mgid=GROUP_ENDPOINT)
PROGRAM.pipe.SwitchIngress.send_to_replicas.set_default_with_send_to_group(mgid=GROUP_REPLICA)

PROGRAM.pipe.SwitchIngressParser.neo_port.add(MULTICAST_PORT)
PROGRAM.pipe.SwitchIngressParser.neo_control_reset_port.add(MULTICAST_CONTROL_RESET_PORT)
PROGRAM.pipe.SwitchIngress.neo.set_default_with_neo_multicast(port=MULTICAST_PORT)
