import struct
import hashlib
import os
import pandas as pd
import random

# Global dictionary to store mappings for each octet
ip_octet_map = [{} for _ in range(4)]  # One dict for each octet position


def hash_with_salt(value,SALT):
    """Hashes a value using SHA-256 with a salt."""
    salted_value = SALT + value.encode()
    return hashlib.sha256(salted_value).hexdigest()

def anonymize_ip_column(ip_series: pd.Series,SALT) -> pd.Series:
    """Anonymize IP addresses while preserving subnet structure."""
    unique_ips = ip_series.unique()

    anonymized_ips = {}
    for ip in unique_ips:
        if ip not in anonymized_ips:
            parts = ip.split(".")
            if len(parts) != 4:
                anonymized_ips[ip] = ip  # Skip invalid IPs
                continue

            anonymized_parts = []
            for i, part in enumerate(parts):
                if part not in ip_octet_map[i]:  # If not already mapped
                    hashed_value = hash_with_salt(part,SALT)
                    # get integer from hash
                    int_hash = int(hashed_value, 16)
                    mapped_octet = int_hash % 256   # Map to 0-255
                    ip_octet_map[i][part] = str(mapped_octet)  # Store mapping
                
                anonymized_parts.append(ip_octet_map[i][part])

            anonymized_ips[ip] = ".".join(anonymized_parts)

    return ip_series.map(anonymized_ips)



#main

if __name__ == "__main__":
    SALT = os.urandom(16)

# Sample IP addresses in a Pandas Series
    ips = pd.Series(["192.168.1.10", "192.168.1.11", "10.0.0.1"])
    
    # Apply anonymization
    anonymized = anonymize_ip_column(ips, SALT)
    # Output original and anonymized IPs
    print(pd.DataFrame({"Original IP": ips, "    Anonymized IP": anonymized}))