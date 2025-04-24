import re
import json

def extract_positions(file_path):
    """Extract IP and port positions from a log file."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    port_pattern = r'\b\d{1,5}\b'

    with open(file_path, 'r') as f:
        lines = f.readlines()

    ip_map = {}   # {original_ip: [(line, offset), ...]}
    port_map = {} # {original_port: [(line, offset), ...]}

    for i, line in enumerate(lines):
        for match in re.finditer(ip_pattern, line):
            ip = match.group()
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append((i, match.start()))

        for match in re.finditer(port_pattern, line):
            if not re.match(ip_pattern, match.group()):  # Ensure it's not an IP
                port = match.group()
                if port not in port_map:
                    port_map[port] = []
                port_map[port].append((i, match.start()))

    return ip_map, port_map

# Input log files
original_log = "suricata_logs.txt"
anonymized_log = "anonymized_suricata.txt"

# Extract data
ip_positions_orig, port_positions_orig = extract_positions(original_log)
ip_positions_anon, port_positions_anon = extract_positions(anonymized_log)

# Dictionary to store mappings
ip_mapping = {}   # {original_ip: {"anonymized_ip": ip, "positions": [(line, offset), ...]}}
port_mapping = {} # {original_port: {"anonymized_port": port, "positions": [(line, offset), ...]}}

# Map IPs
if len(ip_positions_orig) == len(ip_positions_anon):
    for (orig_ip, orig_positions), (anon_ip, _) in zip(ip_positions_orig.items(), ip_positions_anon.items()):
        ip_mapping[orig_ip] = {"anonymized_ip": anon_ip, "positions": orig_positions}
else:
    print(f"⚠️ Warning: IP count mismatch! Original: {len(ip_positions_orig)}, Anonymized: {len(ip_positions_anon)}")

# Map Ports
if len(port_positions_orig) == len(port_positions_anon):
    for (orig_port, orig_positions), (anon_port, _) in zip(port_positions_orig.items(), port_positions_anon.items()):
        port_mapping[orig_port] = {"anonymized_port": anon_port, "positions": orig_positions}
else:
    print(f"⚠️ Warning: Port count mismatch! Original: {len(port_positions_orig)}, Anonymized: {len(port_positions_anon)}")

# Save the mappings as JSON
with open("ip_mapping.json", "w") as f:
    json.dump(ip_mapping, f, indent=4)

with open("port_mapping.json", "w") as f:
    json.dump(port_mapping, f, indent=4)

# Print sample output
print("\n=== Sample IP Mapping ===")
print(json.dumps(dict(list(ip_mapping.items())[:5]), indent=4))  # Print only first 5 entries

print("\n=== Sample Port Mapping ===")
print(json.dumps(dict(list(port_mapping.items())[:5]), indent=4))  # Print only first 5 entries
