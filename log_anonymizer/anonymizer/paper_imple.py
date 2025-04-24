import csv
import hashlib
import json
import sys
import os
import base64
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class CryptoPAn:
    """Crypto-PAn implementation for prefix-preserving anonymization."""
    
    def __init__(self, key):
        """
        Initialize the CryptoPAn object with a key.
        The key is hashed using SHA-256 to generate a 256-bit key for AES.
        """
        self.key = hashlib.sha256(key.encode('utf-8')).digest()  # 256-bit key
        self.cipher = AES.new(self.key, AES.MODE_ECB)  # AES in ECB mode

    def anonymize_ip(self, ip_address):
        """
        Anonymize an IP address while preserving its prefix structure.
        The last octet (8 bits) remains unchanged.
        """
        ip_bin = self._ip_to_bin(ip_address)
        anonymized_bin = self._prefix_preserving_encrypt(ip_bin[:24]) + ip_bin[24:]
        return self._bin_to_ip(anonymized_bin)

    def _ip_to_bin(self, ip_address):
        parts = list(map(int, ip_address.split('.')))
        ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        return format(ip_int, '032b')

    def _bin_to_ip(self, ip_bin):
        ip_int = int(ip_bin, 2)
        return f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"

    def _prefix_preserving_encrypt(self, ip_bin_24):
        """Encrypt the first 24 bits of the IP address while preserving prefix structure."""
        encrypted_bits = ""
        
        for i in range(24):
            input_data = (encrypted_bits + ip_bin_24[len(encrypted_bits):]).ljust(32, '0')
            input_data = int(input_data, 2).to_bytes(4, byteorder='big')
            aes_input = input_data.ljust(16, b'\x00')
            prf_output = self.cipher.encrypt(aes_input)
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            encrypted_bit = '1' if (prf_output[byte_index] & (1 << bit_index)) else '0'
            encrypted_bits += encrypted_bit
        
        return encrypted_bits

def hash_network_part(ip_address):
    """Anonymize the network part of an IP address using Crypto-PAn."""
    key = "my_secure_key"
    cryptopan = CryptoPAn(key)
    return cryptopan.anonymize_ip(ip_address)

def add_laplace_noise(value, scale=1.0):
    """Add Laplace noise to a numerical value for differential privacy."""
    noise = np.random.laplace(loc=0, scale=scale)
    return max(0, int(value + noise))

def anonymize_ip_addresses(ip_column, k):
    """
    Anonymize IP addresses using prefix-preserving anonymization and clustering.
    """
    D = [{'ip': ip} for ip in ip_column]
    
    for record in D:
        record['ip'] = hash_network_part(record['ip'])
    
    ip_addresses = [record['ip'] for record in D]
    host_numbers = [int(ip.split('.')[-1]) for ip in ip_addresses]
    host_numbers = np.array(host_numbers).reshape(-1, 1)
    
    kmeans = KMeans(n_clusters=k)
    clusters = kmeans.fit_predict(host_numbers)
    
    cluster_sizes = np.bincount(clusters)
    sorted_clusters = np.argsort(cluster_sizes)
    
    for j in sorted_clusters:
        if cluster_sizes[j] < k:
            cluster_center = kmeans.cluster_centers_[j]
            distances = pairwise_distances(host_numbers, [cluster_center])
            closest_indices = np.argsort(distances.flatten())
            
            for idx in closest_indices:
                if clusters[idx] != j and cluster_sizes[clusters[idx]] > k:
                    clusters[idx] = j
                    cluster_sizes[j] += 1
                    cluster_sizes[clusters[idx]] -= 1
                    if cluster_sizes[j] >= k:
                        break
    
    for j in range(k):
        cluster_indices = np.where(clusters == j)[0]
        if len(cluster_indices) > 0:
            mean_host_number = int(np.mean([host_numbers[idx] for idx in cluster_indices]))
            for idx in cluster_indices:
                ip_parts = ip_addresses[idx].split('.')
                epsilon = 1
                ip_parts[-1] = str(add_laplace_noise(mean_host_number, scale=1.0/epsilon))
                D[idx]['ip'] = '.'.join(ip_parts)
    
    return [record['ip'] for record in D]

def anonymize_field(value, column_name):
    """Anonymize a field using salting."""
    salt = b"random_salt_value"
    salted_value = salt + value.encode('utf-8')
    hashed_value = hashlib.sha256(salted_value).hexdigest()
    return f"{column_name}<{hashed_value}>"

if __name__ == "__main__":
    test_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
    k = 2
    
    print("Original IPs:")
    print(test_ips)
    
    anonymized_ips = anonymize_ip_addresses(test_ips, k)
    
    print("Anonymized IPs:")
    print(anonymized_ips)
    
    print("Anonymized field example:")
    print(anonymize_field("test_value", "SampleField"))
