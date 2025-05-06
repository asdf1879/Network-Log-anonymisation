import re
import pandas as pd
from datetime import datetime

def parse_logs(log_file, log_type, temp_csv, mapping_file,config=None):
    
    logs = []
    mapping = []

    if log_type == "syslog":
        # Syslog-specific parsing with message decomposition
        syslog_header = re.compile(
            r"<(?P<priority>\d+)>"
            r"(?P<version>\d+)? "  # Optional RFC 5424 version
            r"(?P<timestamp>\S+)\s"  # RFC 3339 timestamp
            r"(?P<hostname>\S+)\s"
            r"(?P<app_name>\S+)\s"
            r"(?P<proc_id>\S+)\s"
            r"(?P<msg_id>\S+)\s"
            r"(?P<structured_data>\S+)\s"  # RFC 5424 structured data
            r"?(?P<message>.*)"  # Free-form message
        )
        
        with open(log_file, "r") as f:
            for line_no, line in enumerate(f, start=1):
                header_match = syslog_header.match(line)
                if not header_match:
                    continue
                
                log_entry = header_match.groupdict()
                log_entry["line_no"] = line_no
                
                # Additional parsing for structured data
                if log_entry['structured_data'] != '-':
                    sd_parser = re.finditer(
                        r"(?P<param_name>\w+)=\"(?P<param_value>[^\"]*)\"",
                        log_entry['structured_data']
                    )
                    for match in sd_parser:
                        log_entry[match.group('param_name')] = match.group('param_value')
                
                # Extract key-value pairs from message body
                kv_pairs = re.findall(
                    r"\b(?P<key>\w+)=[\"']?(?P<value>[^\"'\s]+)", 
                    log_entry['message']
                )
                for key, value in kv_pairs:
                    log_entry[key] = value
                
                logs.append(log_entry)
                
                # Store mapping
                mapping_fields = ["timestamp", "hostname", "app_name", "src_ip", "dest_ip"]
                for field in mapping_fields:
                    if field in log_entry:
                        mapping.append({
                            "line_no": line_no,
                            "field": field,
                            "original_value": log_entry[field]
                        })

    elif log_type == "pfsense":
        # Existing pfSense parsing
        pattern = re.compile(
            r"(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<process>\S+): "
            r"(?P<rule>\d+) rule \S+ \((?P<match>.*?)\) (?P<action>\w+) (?P<direction>\w+) on (?P<interface>\S+): "
            r"\(proto (?P<protocol>\S+) .*?\) (?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) > "
            r"(?P<dest_ip>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)"
        )

        logs, mapping = _generic_parser(log_file, pattern)

    elif log_type in ["suricata", "firewall", "zeek"]:
        # Existing parsers for other types
        if log_type == "zeek":
            return _handle_zeek(log_file, temp_csv)
            
        pattern = {
            "suricata": re.compile(
                r"(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)  \[\*\*\] (?P<alert>.*?) \[\*\*\] "
                r"\[Classification: (?P<classification>.*?)\] \[Priority: (?P<priority>\d+)\] "
                r"\{(?P<protocol>.*?)\} (?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) -> "
                r"(?P<dest_ip>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)"
            ),
            "firewall": re.compile(
                r"(?P<timestamp>[\w\s:]+) SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+) DST=(?P<dest_ip>\d+\.\d+\.\d+\.\d+) "
                r"SPT=(?P<src_port>\d+) DPT=(?P<dest_port>\d+)"
            )
        }[log_type]
        logs, mapping = _generic_parser(log_file, pattern)

    elif log_type == "custom":
        pattern = config.get("anonymization", {}).get("custom_format", {}).get("pattern")
        # print(config)
        if not pattern:
            raise ValueError("Custom format specified but no pattern provided in config.")
        pattern = re.compile(pattern)
        logs, mapping = _custom_parser(log_file, pattern,config)
    # Save results
    df_logs = pd.DataFrame(logs)
    df_mapping = pd.DataFrame(mapping)

    df_logs.to_csv(temp_csv, index=False)
    df_mapping.to_csv(mapping_file, index=False)

    print(f"✅ Temporary structured logs saved in {temp_csv}")
    return df_logs, df_mapping

def _generic_parser(log_file, pattern):
    """Handles common parsing flow for non-Syslog types"""
    logs = []
    mapping = []
    
    with open(log_file, "r") as f:
        for line_no, line in enumerate(f, start=1):
            match = pattern.search(line)
            if match:
                log_entry = match.groupdict()
                log_entry["line_no"] = line_no
                logs.append(log_entry)

                for field in ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port"]:
                    if field in log_entry:
                        if field in match.re.groupindex:
                            offset = match.start(field)  # 👈 this gives position of field in line
                        else:
                            offset = -1 
                        mapping.append({
                            "line_no": line_no,
                            "field": field,
                            "original_value": log_entry[field],
                            "offset" : offset
                        })
    return logs, mapping

def _custom_parser(log_file, pattern, config):
    logs = []
    mapping = []

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            match = pattern.search(line)
            if match:
                log_entry = match.groupdict()
                log_entry["line_no"] = line_no
                logs.append(log_entry)
                fields_from_config = config.get("anonymization", {}).get("custom_format", {}).get("fields", [])
                for field in fields_from_config:
                    # print(f"field is {field}")
                    if field in log_entry:
                        if field in match.re.groupindex:
                            offset = match.start(field)  # 👈 this gives position of field in line
                        else:
                            offset = -1 
                        mapping.append({
                            "line_no": line_no,
                            "field": field,
                            "original_value": log_entry[field],
                            "offset" : offset
                        })
    return logs, mapping

def _handle_zeek(log_file, temp_csv):
    """Special handling for Zeek logs"""
    df = pd.read_csv(log_file, delimiter="\t", comment='#', header=None)
    df.columns = ["timestamp", "uid", "src_ip", "src_port", "dest_ip", "dest_port", "protocol", "service"]
    df.to_csv(temp_csv, index=False)
    print(f"✅ Temporary structured logs saved in {temp_csv}")
    return df, None







def main():
    # Predefined log entries for testing
    suricata_log = (
        "04/13/2025-14:02:15.123  [**] Test Alert [**] [Classification: Test Classification] [Priority: 1] "
        "{TCP} 192.168.1.1:12345 -> 10.0.0.1:80"
    )
    firewall_log = (
        "Apr 13 14:02:15 SRC=192.168.1.2 DST=10.0.0.2 SPT=12346 DPT=443"
    )
    zeek_log = (
        "2025-04-13T14:02:15.123Z\tC1\t192.168.1.3\t12347\t10.0.0.3\t22\tTCP\tssh"
    )
    syslog_log = (
        "<13>1 2025-04-13T14:02:15.123Z host1 app_name 1234 ID1 [exampleSDID@32473 key1=\"value1\" key2=\"value2\"] "
        "src_ip=192.168.1.4 dest_ip=10.0.0.4 action=ALLOW"
    )
    pfsense_log = (
        "Apr 13 14:02:15 pfsense filterlog: 1000 rule 0/(match) pass in on em0: (proto TCP (ACK)) "
        "192.168.1.5:12348 > 10.0.0.5:80"
    )

    # Save logs to temporary files for testing
    with open("test_suricata.log", "w") as f:
        f.write(suricata_log + "\n")
    with open("test_firewall.log", "w") as f:
        f.write(firewall_log + "\n")
    with open("test_zeek.log", "w") as f:
        f.write(zeek_log + "\n")
    with open("test_syslog.log", "w") as f:
        f.write(syslog_log + "\n")
    with open("test_pfsense.log", "w") as f:
        f.write(pfsense_log + "\n")

    # Test parsing functionality
    print("\nTesting Suricata parsing:")
    df_suricata, _ = parse_logs("test_suricata.log", "suricata", "suricata_output.csv", "suricata_mapping.csv")
    print(df_suricata)

    print("\nTesting Firewall parsing:")
    df_firewall, _ = parse_logs("test_firewall.log", "firewall", "firewall_output.csv", "firewall_mapping.csv")
    print(df_firewall)

    print("\nTesting Zeek parsing:")
    df_zeek, _ = parse_logs("test_zeek.log", "zeek", "zeek_output.csv", None)
    print(df_zeek)

    print("\nTesting Syslog parsing:")
    df_syslog, _ = parse_logs("test_syslog.log", "syslog", "syslog_output.csv", "syslog_mapping.csv")
    print(df_syslog)

    print("\nTesting pfSense parsing:")
    df_pfsense, _ = parse_logs("test_pfsense.log", "pfsense", "pfsense_output.csv", "pfsense_mapping.csv")
    print(df_pfsense)

if __name__ == "__main__":
    main()
