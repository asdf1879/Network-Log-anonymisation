import pandas as pd

def replace_anonymized_values(mapping_file, anonymized_csv, original_log_file, output_log_file):
    """Replace anonymized values back into the original log format."""
    
    df_mapping = pd.read_csv(mapping_file)
    df_anonymized = pd.read_csv(anonymized_csv)

    # Convert anonymized values into a lookup dictionary
    anon_lookup = {}
    for _, row in df_anonymized.iterrows():
        anon_lookup[(row["line_no"], "timestamp")] = str(row["timestamp"])
        anon_lookup[(row["line_no"], "src_ip")] = str(row["src_ip"])
        anon_lookup[(row["line_no"], "dest_ip")] = str(row["dest_ip"])
        anon_lookup[(row["line_no"], "src_port")] = str(row["src_port"])
        anon_lookup[(row["line_no"], "dest_port")] = str(row["dest_port"])

    # Read original logs & replace values column-wise
    reconstructed_logs = []
    with open(original_log_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            for field in ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port"]:
                if (line_no, field) in anon_lookup:
                    original_value = df_mapping.loc[
                        (df_mapping["line_no"] == line_no) & (df_mapping["field"] == field), "original_value"
                    ].values[0]

                    anonymized_value = anon_lookup.get((line_no, field), original_value)

                    if original_value and anonymized_value and original_value in line:
                        line = line.replace(original_value, anonymized_value, 1)

            reconstructed_logs.append(line.strip())

    # Save reconstructed logs
    with open(output_log_file, "w", encoding="utf-8") as f:
        f.write("\n".join(reconstructed_logs))

    print(f"✅ Reconstructed logs saved in {output_log_file}")
