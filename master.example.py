from subprocess import Popen
from socket import gethostname
from pathlib import Path
from signal import SIGINT
from sys import argv
from time import sleep


TASK = {
    "mode": "ur",
    "assume_byz": False,
    "num_client": 1,
    "num_worker": 1,
    "enable_batching": True,
}

DB = [
    {
        "hostname": "node1",
        "address": "10.0.0.1:2023",
        "mac": 0x000001000001,
        "physical_port": 0,
        "dev_port": 0,
        "role": "replica",
        "index": 0,
    },
    {
        "hostname": "node2",
        "address": "10.0.0.2:2023",
        "mac": 0x000001000002,
        "physical_port": 1,
        "dev_port": 4,
        "role": "replica",
        "index": 1,
    },
    {
        "hostname": "node3",
        "address": "10.0.0.3:2023",
        "mac": 0x000001000003,
        "physical_port": 2,
        "dev_port": 8,
        "role": "replica",
        "index": 2,
    },
    {
        "hostname": "node4",
        "address": "10.0.0.4:2023",
        "mac": 0x000001000004,
        "physical_port": 3,
        "dev_port": 12,
        "role": "replica",
        "index": 3,
    },
    {
        "hostname": "node5",
        "ip": "10.0.0.101",
        "mac": 0x000001000005,
        "physical_port": 4,
        "dev_port": 16,
        "speed": "40G",
        "role": "client",
    },
    {
        "hostname": "sw",
        "role": "switch",
    },
    {
        "hostname": None,
        "role": "switch_accel",
        "physical_port": 63,
        "dev_port": 32,
    },
]

WS = Path.home() / "neo_workspace"
ARTIFACT_REPLICA = "user@host:~/neoart/target/release/replica"
ARTIFACT_CLIENT = "user@host:~/neoart/target/release/client"
ARTIFACT_MASTER_PY = "cowsay@nsl-node4.d1:~/neoart/master.py"
ARTIFACT_P4SRC = "cowsay@nsl-node4.d1:~/neoart/p4src"


def query_replica_address(index):
    for entry in DB:
        if entry["role"] == "replica" and entry["index"] == index:
            return entry["address"]
    assert False, "not found"


def query(key):
    hostname = gethostname()
    for entry in DB:
        if entry["hostname"] == hostname:
            return entry[key]


def execute(cmd, check=True, shell=False, cwd=WS):
    if not shell:
        cmd = tuple(str(arg) for arg in cmd)
        print("> " + " ".join(cmd))
    else:
        print("> " + cmd)
    proc = Popen(cmd, shell=shell, cwd=cwd)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(SIGINT)
        proc.wait(timeout=0)
    if check:
        assert proc.returncode == 0, f"exit code: {proc.returncode}"


def create_config():
    if TASK["mode"] == "ur":
        config = "f 0\nreplica " + query_replica_address(0)
    else:
        config = "f 1\n"
        for i in range(4):
            config += f"replica {query_replica_address(i)}\n"
    (WS / "config.txt").write_text(config)


def create_ports():
    setup = """
ucli
pm
"""
    for entry in DB:
        if "physical_port" in entry:
            setup += (
                "port-add "
                + str(entry["physical_port"])
                + "/- "
                + entry.get("speed", "100G")
                + " NONE\n"
            )
    setup += """
an-set -/- 2
port-enb -/-
..
exit
exit
"""
    (WS / "ports").write_text(setup)


def switch_init(pre, p4, db):
    ingress = p4.pipe.SwitchIngress
    replicas, clients = [], []
    for entry in db:
        if "mac" in entry:
            ingress.dmac.add_with_send(dst_addr=entry["mac"], port=entry["dev_port"])

        if entry["role"] == "replica":
            replicas.append(entry["dev_port"])
        elif entry["role"] == "client":
            clients.append(entry["dev_port"])
        elif entry["role"] == "switch_accel":
            ingress.from_accel.add_with_nop(ingress_port=entry["dev_port"])
            ingress.send_to_accel.set_default_with_send(port=entry["dev_port"])
    endpoint_id, replica_id = 1, 2
    rid = 0xFFFF
    pre.node.add(endpoint_id, rid, [], replicas + clients)
    pre.mgid.add(endpoint_id, [endpoint_id], [0], [0])
    pre.node.add(replica_id, rid, [], replicas)
    pre.mgid.add(replica_id, [replica_id], [0], [0])
    ingress.send_to_endpoints.set_default_with_send_to_group(mgid=endpoint_id)
    ingress.send_to_replicas.set_default_with_send_to_group(mgid=replica_id)


assert __name__ in ("__main__", "bfrtcli")

try:
    p4, pre = bfrt.neo_r, bfrt.pre
    role = "switch_bfrt"
except NameError:
    print("* master script start")
    role = query("role")
    print("* create workspace directory")
    WS.mkdir(exist_ok=True)

if not role:
    exit(0)
if role == "replica" or role == "client":
    print("* create configuration for " + TASK["mode"])
    create_config()

if role == "replica":
    print("* update replica artifact")
    execute(["rsync", ARTIFACT_REPLICA, WS / "replica"])
    print("* run replica")
    cmd = [
        WS / "replica",
        "-c",
        WS / "config.txt",
        "-m",
        TASK["mode"],
        "-i",
        query("index"),
        "-t",
        TASK["num_worker"],
    ]
    if TASK["enable_batching"]:
        cmd += ["-b"]
    execute(cmd)

elif role == "client":
    print("* update client artifact")
    execute(["rsync", ARTIFACT_CLIENT, WS / "client"])
    print("* run client")
    cmd = [
        WS / "client",
        "-c",
        WS / "config.txt",
        "-h",
        query("ip"),
        "-m",
        TASK["mode"] if not TASK["assume_byz"] else TASK["mode"] + "-byz",
        "-t",
        TASK["num_client"],
    ]
    execute(cmd)

elif role == "switch":
    program = "neo_r"

    if (argv + [""])[1] == "init":
        execute(f"$SDE/run_bfshell.sh -f {WS}/ports", shell=True)
        sleep(1)
        execute(f"$SDE/run_bfshell.sh -b {WS}/master.py", shell=True)
        sleep(1)
    else:
        print("* update switch artifacts")
        create_ports()
        execute(["rsync", ARTIFACT_MASTER_PY, WS / "master.py"])
        execute(["rsync", f"{ARTIFACT_P4SRC}/*", WS])

elif role == "switch_bfrt":
    switch_init(pre, p4, DB)
