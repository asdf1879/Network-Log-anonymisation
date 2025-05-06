import argparse
import yaml
import pandas as pd
from anonymizer.log_parser import parse_logs
from anonymizer.log_reconstructor import replace_anonymized_values
from anonymizer.ip_anonymizer import anonymize_ip_column
from anonymizer.port_anonymizer import anonymize_port_column
from anonymizer.timestamp_anonymizer import round_to_nearest_15_minutes_column
from anonymizer.timestamp_anonymizer import perturb_time_column, bucketize_dates_column, order_preserving_adaptive_noise
from anonymizer.ipmask import generalize_ip
from anonymizer.differential import add_noise
from anonymizer.paper_imple import anonymize_ip_addresses
from anonymizer.convert_to_ocsf import convert_to_ocsf
import os

def load_config(config_path):
    """Load anonymization settings from a YAML config file."""
    with open(config_path, "r") as file:
        return yaml.safe_load(file)

def main():
    SALT = os.urandom(16)
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
    df_logs, df_mapping = parse_logs(log_file, log_type, temp_csv, mapping_file,config)
    
    ocsffile = "ocsf_logs.json"
    # Convert to OCSF format
    convert_to_ocsf(df_logs, log_type, ocsffile)

    if log_type == "custom":
        custom_format = anonymization.get("custom_format", {})
        fields = custom_format.get("fields", [])  # Directly use the list

        for field in fields:
            if field in df_logs.columns and field in custom_format:
                strategy = custom_format[field]

                if strategy == "salt":
                    if "ip" in field:
                        df_logs[field] = anonymize_ip_column(df_logs[field], SALT)
                    else:
                        df_logs[field] = anonymize_port_column(df_logs[field], SALT)  # or another general salt-based strategy

                elif strategy == "mask" and "ip" in field:
                    df_logs[field] = generalize_ip(df_logs[field], 24)

                elif strategy == "condensation" and "ip" in field:
                    df_logs[field] = anonymize_ip_addresses(df_logs[field], 5)

                elif strategy == "differential":
                    df_logs[field] = add_noise(df_logs[field], epsilon=1.0)

                elif strategy == "adaptive" and "timestamp" in field:
                    df_logs[field] = order_preserving_adaptive_noise(df_logs[field], apply_global_offset=True)

                elif strategy == "perturb" and "timestamp" in field:
                    df_logs[field] = perturb_time_column(df_logs[field], window_minutes=5)

                elif strategy == "round" and "timestamp" in field:
                    df_logs[field] = round_to_nearest_15_minutes_column(df_logs[field])


    else:

        # Step 2: Apply anonymization methods based on config
        if "timestamp" in anonymization:
            if anonymization["timestamp"] == "round":
                df_logs["timestamp"] = round_to_nearest_15_minutes_column(df_logs["timestamp"])
            if anonymization["timestamp"] == "perturb":
                df_logs["timestamp"] = perturb_time_column(df_logs["timestamp"], window_minutes=5)
            if anonymization["timestamp"] == "bucketize":
                df_logs["timestamp"] = bucketize_dates_column(df_logs["timestamp"], resolution="day")
            if anonymization["timestamp"] == "adaptive":
                df_logs["timestamp"] = order_preserving_adaptive_noise(df_logs["timestamp"], apply_global_offset=True)
            

        if "ip" in anonymization:
            if anonymization["ip"] == "salt":
                df_logs["src_ip"] = anonymize_ip_column(df_logs["src_ip"],SALT)
                df_logs["dest_ip"] = anonymize_ip_column(df_logs["dest_ip"],SALT)
            if anonymization["ip"] == "mask":
                df_logs["src_ip"] = generalize_ip(df_logs["src_ip"], 24)
                df_logs["dest_ip"] = generalize_ip(df_logs["dest_ip"], 24)
            if anonymization["ip"] == "condensation" :
                df_logs["src_ip"] = anonymize_ip_addresses(df_logs["src_ip"], 5)
                df_logs["dest_ip"] = anonymize_ip_addresses(df_logs["dest_ip"], 5)

            
        if "port" in anonymization:
            if anonymization["port"] == "salt":
                df_logs["src_port"] = anonymize_port_column(df_logs["src_port"], SALT)
                df_logs["dest_port"] = anonymize_port_column(df_logs["dest_port"], SALT)
        
        if "data" in anonymization:
            if anonymization["data"] == "differential":
                df_logs["data"] = add_noise(df_logs["data"], epsilon=1.0)
        

    # Save anonymized CSV
    df_logs.to_csv(anonymized_csv, index=False)
    print(f"✅ Anonymized logs saved in {anonymized_csv}")

    # Step 3: Replace anonymized values back into logs
    replace_anonymized_values(mapping_file, anonymized_csv, log_file, output_log)

if __name__ == "__main__":
    main()
