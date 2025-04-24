import pandas as pd

def replace_anonymized_values(mapping_file, anonymized_csv, original_log_file, output_log_file):
    """Replace anonymized values back into the original log format using exact field offsets."""

    import pandas as pd

    df_mapping = pd.read_csv(mapping_file)
    df_anonymized = pd.read_csv(anonymized_csv)

    # Build dynamic lookup for anonymized fields
    anon_lookup = {}
    for _, row in df_anonymized.iterrows():
        line_no = row['line_no']
        for field in df_anonymized.columns:
            if field == 'line_no':
                continue
            anon_lookup[(line_no, field)] = str(row[field])

    # Group mapping entries by line number
    grouped_mappings = df_mapping.groupby("line_no")

    reconstructed_logs = []

    with open(original_log_file, "r", encoding="utf-8") as f:
        for current_line_no, line in enumerate(f, start=1):
            line = list(line)  # Convert to list of characters for safe in-place mutation

            if current_line_no in grouped_mappings.groups:
                line_mappings = grouped_mappings.get_group(current_line_no)

                # Sort by offset descending to avoid messing up indexes
                line_mappings = line_mappings.sort_values("offset", ascending=False)

                for _, entry in line_mappings.iterrows():
                    field = entry["field"]
                    offset = int(entry["offset"])
                    original_val = str(entry["original_value"])
                    anon_val = anon_lookup.get((current_line_no, field), original_val)

                    # Replace in-place
                    if line[offset:offset+len(original_val)] == list(original_val):
                        line[offset:offset+len(original_val)] = list(anon_val)

            reconstructed_logs.append("".join(line))

    # Write reconstructed logs
    with open(output_log_file, "w", encoding="utf-8") as f_out:
        f_out.writelines(reconstructed_logs)


    print(f"✅ Reconstructed logs saved in {output_log_file}")
