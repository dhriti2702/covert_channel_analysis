import json
import pymysql  # or sqlite3 depending on your DB
from pathlib import Path

# Get the base directory (aiml_dbms_lab)
BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURED_JSON = BASE_DIR / "CapturePackets" / "captured.json"
FLOW_TABLE_JSON = BASE_DIR / "CapturePackets" / "flow_table.json"

# -----------------------
# 1. Read packets from captured.json and flows from flow_table.json
# -----------------------
with open(CAPTURED_JSON, "r") as f:
    packets = json.load(f)

with open(FLOW_TABLE_JSON, "r") as f:
    flows = json.load(f)

# Create mapping from string flow_id to numeric FlowID
# flow_id format from capture: "ip:port-ip:port" (sorted by tuple comparison)
# We need to match both possible orderings since flow direction can vary
flow_id_to_flowid = {}
for flow in flows:
    # Create both possible flow_id formats (forward and reverse)
    src_key = f"{flow['SourceIP']}:{flow['SourcePort']}"
    dst_key = f"{flow['DestinationIP']}:{flow['DestinationPort']}"
    # Try both orderings
    flow_id_1 = f"{src_key}-{dst_key}"
    flow_id_2 = f"{dst_key}-{src_key}"
    # Also try sorted version (canonical)
    endpoints = sorted([src_key, dst_key])
    canonical_flow_id = f"{endpoints[0]}-{endpoints[1]}"
    # Map all three to the same FlowID
    flow_id_to_flowid[flow_id_1] = flow["FlowID"]
    flow_id_to_flowid[flow_id_2] = flow["FlowID"]
    flow_id_to_flowid[canonical_flow_id] = flow["FlowID"]

# -----------------------
# 2. Connect to database
# -----------------------
db = pymysql.connect(
    host="localhost",
    user="root",
    password="",  # No password for root user
    database="COVERT_CHANNEL"
)

cursor = db.cursor()

# -----------------------
# 3. Insert each packet
# -----------------------
sql = """
INSERT INTO packet (
    packet_id, flow_id, timestamp, src_ip, dst_ip,
    src_port, dst_port, protocol, packet_length,
    ip_total_length, ip_header_length, ethernet_header_length,
    tcp_header_length, tcp_payload_length, seq, ack,
    tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg,
    ip_flags, ip_ttl, tcp_window, tcp_dataofs, tcp_reserved,
    IPID, IAT, Label
)
VALUES (%s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s)
ON DUPLICATE KEY UPDATE
    flow_id=VALUES(flow_id),
    timestamp=VALUES(timestamp),
    src_ip=VALUES(src_ip),
    dst_ip=VALUES(dst_ip),
    src_port=VALUES(src_port),
    dst_port=VALUES(dst_port),
    protocol=VALUES(protocol),
    packet_length=VALUES(packet_length),
    ip_total_length=VALUES(ip_total_length),
    ip_header_length=VALUES(ip_header_length),
    ethernet_header_length=VALUES(ethernet_header_length),
    tcp_header_length=VALUES(tcp_header_length),
    tcp_payload_length=VALUES(tcp_payload_length),
    seq=VALUES(seq),
    ack=VALUES(ack),
    tcp_fin=VALUES(tcp_fin),
    tcp_syn=VALUES(tcp_syn),
    tcp_rst=VALUES(tcp_rst),
    tcp_psh=VALUES(tcp_psh),
    tcp_ack=VALUES(tcp_ack),
    tcp_urg=VALUES(tcp_urg),
    ip_flags=VALUES(ip_flags),
    ip_ttl=VALUES(ip_ttl),
    tcp_window=VALUES(tcp_window),
    tcp_dataofs=VALUES(tcp_dataofs),
    tcp_reserved=VALUES(tcp_reserved),
    IPID=VALUES(IPID),
    IAT=VALUES(IAT),
    Label=VALUES(Label)
"""

for pkt in packets:
    # Map string flow_id to numeric FlowID
    string_flow_id = pkt["flow_id"]
    numeric_flow_id = flow_id_to_flowid.get(string_flow_id, None)
    
    if numeric_flow_id is None:
        print(f"Warning: No matching FlowID found for flow_id '{string_flow_id}', skipping packet {pkt['packet_id']}")
        continue
    
    values = (
        pkt["packet_id"],
        numeric_flow_id,  # Use numeric FlowID instead of string flow_id
        pkt["timestamp"],
        pkt["src_ip"],
        pkt["dst_ip"],
        pkt["src_port"],
        pkt["dst_port"],
        pkt["protocol"],
        pkt["packet_length"],
        pkt["ip_total_length"],
        pkt["ip_header_length"],
        pkt["ethernet_header_length"],
        pkt["tcp_header_length"],
        pkt["tcp_payload_length"],
        pkt["seq"],
        pkt["ack"],
        pkt["tcp_fin"],
        pkt["tcp_syn"],
        pkt["tcp_rst"],
        pkt["tcp_psh"],
        pkt["tcp_ack"],
        pkt["tcp_urg"],
        pkt["ip_flags"],
        pkt["ip_ttl"],
        pkt["tcp_window"],
        pkt["tcp_dataofs"],
        pkt["tcp_reserved"],
        pkt["IPID"],
        pkt["IAT"],
        pkt["Label"]
    )

    cursor.execute(sql, values)

db.commit()
cursor.close()
db.close()

print("Packets inserted successfully!")