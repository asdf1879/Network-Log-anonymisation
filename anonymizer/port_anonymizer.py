import hashlib
import os
import pandas as pd

# Global port mapping
port_map = {}
SALT = os.urandom(16)

def hash_with_salt(value):
    """Hashes a value using SHA-256 with a salt and returns a full hex digest."""
    salted_value = SALT + value.encode()
    return hashlib.sha256(salted_value).hexdigest()

def anonymize_port_column(port_series: pd.Series) -> pd.Series:
    """Anonymize a column of ports while ensuring stable one-to-one mapping."""
    unique_ports = port_series.unique()

    for port in unique_ports:
        if port not in port_map:
            hashed_value = hash_with_salt(str(port))
            # Convert full hash to an integer and map to valid port range (1024–65535 to avoid reserved ports)
            mapped_port = (int(hashed_value, 16) % (65535 - 1024)) + 1024
            port_map[port] = str(mapped_port)

    return port_series.map(port_map)
