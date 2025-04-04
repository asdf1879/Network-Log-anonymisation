import re
import pandas as pd

def parse_logs(log_file, log_type, temp_csv, mapping_file):
    """
    Parses logs based on the specified type (Suricata, Firewall, Zeek).
    """
    logs = []
    mapping = []

    if log_type == "suricata":
        pattern = re.compile(
            r"(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)  \[\*\*\] (?P<alert>.*?) \[\*\*\] "
            r"\[Classification: (?P<classification>.*?)\] \[Priority: (?P<priority>\d+)\] "
            r"\{(?P<protocol>.*?)\} (?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) -> "
            r"(?P<dest_ip>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)"
        )
    
    elif log_type == "firewall":
        pattern = re.compile(r"(?P<timestamp>[\w\s:]+) SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+) DST=(?P<dest_ip>\d+\.\d+\.\d+\.\d+) SPT=(?P<src_port>\d+) DPT=(?P<dest_port>\d+)")

    elif log_type == "zeek":
        df = pd.read_csv(log_file, delimiter="\t", comment='#', header=None)
        df.columns = ["timestamp", "uid", "src_ip", "src_port", "dest_ip", "dest_port", "protocol", "service"]
        df.to_csv(temp_csv, index=False)
        print(f"✅ Temporary structured logs saved in {temp_csv}")
        return df, None

    with open(log_file, "r") as f:
        for line_no, line in enumerate(f, start=1):
            match = pattern.search(line)
            if match:
                log_entry = match.groupdict()
                log_entry["line_no"] = line_no
                logs.append(log_entry)

                # Store mapping for reconstruction
                for field in ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port"]:
                    mapping.append({"line_no": line_no, "field": field, "original_value": log_entry[field]})

    df_logs = pd.DataFrame(logs)
    df_mapping = pd.DataFrame(mapping)

    df_logs.to_csv(temp_csv, index=False)
    df_mapping.to_csv(mapping_file, index=False)

    print(f"✅ Temporary structured logs saved in {temp_csv}")
    return df_logs, df_mapping
