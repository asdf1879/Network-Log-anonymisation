import re
import pandas as pd

def parse_suricata_logs(log_file, temp_csv="temp_logs.csv", mapping_file="log_mapping.csv"):
    """
    Extracts Suricata log fields and stores them in a structured CSV format.
    Also records the position of each value for later replacement.
    """
    pattern = re.compile(
        r"(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)  \[\*\*\] (?P<alert>.*?) \[\*\*\] "
        r"\[Classification: (?P<classification>.*?)\] \[Priority: (?P<priority>\d+)\] "
        r"\{(?P<protocol>.*?)\} (?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) -> "
        r"(?P<dest_ip>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)"
    )

    logs = []
    mapping = []

    with open(log_file, "r") as f:
        for line_no, line in enumerate(f, start=1):
            match = pattern.search(line)
            if match:
                log_entry = match.groupdict()
                log_entry["line_no"] = line_no
                log_entry["original_log"] = line.strip()
                logs.append(log_entry)

                # Store position of each value for replacement
                for field in ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port"]:
                    mapping.append({"line_no": line_no, "field": field, "original_value": log_entry[field]})

    # Convert logs & mapping to DataFrames and save
    df_logs = pd.DataFrame(logs)
    df_mapping = pd.DataFrame(mapping)

    df_logs.to_csv(temp_csv, index=False)
    df_mapping.to_csv(mapping_file, index=False)

    print(f"Temporary structured logs saved in {temp_csv}")
    print(f"Mapping saved in {mapping_file}")

    return df_logs, df_mapping
