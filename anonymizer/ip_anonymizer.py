import struct
import hashlib
import os
import pandas as pd

# Global dictionary to store mappings for each octet
ip_octet_map = [{} for _ in range(4)]  # One dict for each octet position
SALT = os.urandom(16)

def hash_with_salt(value):
    """Hashes a value using SHA-256 with a salt."""
    salted_value = SALT + value.encode()
    return hashlib.sha256(salted_value).hexdigest()

def anonymize_ip_column(ip_series: pd.Series) -> pd.Series:
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
                    hashed_value = hash_with_salt(part)
                    mapped_octet = int(hashed_value, 16) % 256  # Map to 0-255
                    ip_octet_map[i][part] = str(mapped_octet)  # Store mapping
                
                anonymized_parts.append(ip_octet_map[i][part])

            anonymized_ips[ip] = ".".join(anonymized_parts)

    return ip_series.map(anonymized_ips)
