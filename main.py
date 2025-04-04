import argparse
import yaml
import pandas as pd
from anonymizer.log_parser import parse_logs
from anonymizer.log_reconstructor import replace_anonymized_values
from anonymizer.ip_anonymizer import anonymize_ip_column
from anonymizer.port_anonymizer import anonymize_port_column
from anonymizer.timestamp_anonymizer import round_to_nearest_15_minutes_column

def load_config(config_path):
    """Load anonymization settings from a YAML config file."""
    with open(config_path, "r") as file:
        return yaml.safe_load(file)

def main():
    parser = argparse.ArgumentParser(description="Log Anonymization Tool")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    log_file = config["log_file"]
    log_type = config["log_type"]
    output_log = config["output_log"]
    anonymization = config.get("anonymization", {})

    temp_csv = "temp_logs.csv"
    mapping_file = "log_mapping.csv"
    anonymized_csv = "anonymized_logs.csv"

    # Step 1: Parse logs
    df_logs, df_mapping = parse_logs(log_file, log_type, temp_csv, mapping_file)

    # Step 2: Apply anonymization methods based on config
    if "timestamp" in anonymization:
        if anonymization["timestamp"] == "round":
            df_logs["timestamp"] = round_to_nearest_15_minutes_column(df_logs["timestamp"])
        

    if "ip" in anonymization:
        if anonymization["ip"] == "salt":
            df_logs["src_ip"] = anonymize_ip_column(df_logs["src_ip"])
            df_logs["dest_ip"] = anonymize_ip_column(df_logs["dest_ip"])
        

    if "port" in anonymization:
        if anonymization["port"] == "salt":
            df_logs["src_port"] = anonymize_port_column(df_logs["src_port"])
            df_logs["dest_port"] = anonymize_port_column(df_logs["dest_port"])
        

    # Save anonymized CSV
    df_logs.to_csv(anonymized_csv, index=False)
    print(f"✅ Anonymized logs saved in {anonymized_csv}")

    # Step 3: Replace anonymized values back into logs
    replace_anonymized_values(mapping_file, anonymized_csv, log_file, output_log)

if __name__ == "__main__":
    main()
