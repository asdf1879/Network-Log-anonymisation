import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import jaccard_score
from scipy.stats import entropy
import hashlib
import os
from anonymizer.ip_anonymizer import anonymize_ip_column
from collections import defaultdict

def calculate_collisions(original_series, anonymized_series):
    """Calculate average octet collision rate between original and anonymized IPs"""
    collisions = [defaultdict(set) for _ in range(4)]
    
    original_series = original_series.str.split('.')
    anonymized_series = anonymized_series.str.split('.')
    
    for orig, anon in zip(original_series, anonymized_series):
        for i in range(4):
            collisions[i][anon[i]].add(orig[i])
    
    #print
    for i in range(4):
        for j in range(256):
            print(f"Octet {i} - Value {j}: {len(collisions[i][str(j)])} collisions")


    rates = []
    for i in range(4):
        repeats=0
        total =0
        for j in range(256):
            total += len(collisions[i][str(j)])
            if len(collisions[i][str(j)]) > 1:
                repeats += len(collisions[i][str(j)])-1
        
        rate = repeats / total if total else 0
        rates.append(rate)
    
    return rates # Average collision rate across 4 octets



def calculate_entropy(original_series, anonymized_series):
    """Calculate Shannon entropy difference"""
    orig_counts = original_series.value_counts(normalize=True)
    anon_counts = anonymized_series.value_counts(normalize=True)
    
    H_orig = entropy(orig_counts, base=2)
    H_anon = entropy(anon_counts, base=2)
    
    return H_anon - H_orig

def subnet_preservation(original_ips, anonymized_ips):
    """Calculate Jaccard Index for /24 subnets"""
    orig_subnets = set(ip.rsplit('.', 1)[0] for ip in original_ips)
    anon_subnets = set(ip.rsplit('.', 1)[0] for ip in anonymized_ips)
    
    intersection = orig_subnets & anon_subnets
    union = orig_subnets | anon_subnets
    
    return len(intersection)/len(union) if union else 0

def plot_subnet_heatmap(original_ips, anonymized_ips):
    """Visualize subnet preservation"""
    orig_subnets = pd.Series([ip.rsplit('.', 1)[0] for ip in original_ips])
    anon_subnets = pd.Series([ip.rsplit('.', 1)[0] for ip in anonymized_ips])
    
    plt.figure(figsize=(12, 8))
    sns.heatmap(pd.crosstab(orig_subnets, anon_subnets), cmap='YlGnBu')
    plt.title('Subnet Structure Preservation Heatmap')
    plt.xlabel('Anonymized Subnets')
    plt.ylabel('Original Subnets')
    plt.show()

def port_validity(anonymized_ports):
    """Validate port range and distribution"""
    valid = anonymized_ports.between(0, 65535).mean() * 100
    plt.figure(figsize=(10, 6))
    anonymized_ports.hist(bins=50)
    plt.title('Anonymized Port Number Distribution')
    plt.xlabel('Port Number')
    plt.ylabel('Frequency')
    plt.show()
    return valid

def privacy_utility_score(H_delta, jaccard, collision_rate, weights=(0.4, 0.4, 0.2)):
    """Calculate composite Privacy-Utility Score"""
    return (weights[0] * H_delta + 
            weights[1] * jaccard - 
            weights[2] * collision_rate)

def generate_random_ports(n):
    """Generate random ports for anonymization"""
    return np.random.randint(0, 65536, n)

# Example usage with sample data
if __name__ == "__main__":
    # Generate test data
    
    df = pd.read_csv('Dataset_IP.csv', nrows=10000)

    # print(df.head())
    
    # Anonymize data using your technique
    SALT = os.urandom(16)
    df['anon_ip'] = anonymize_ip_column(df['IP Address'], SALT)
    df['port'] = generate_random_ports(len(df))
    df['anon_port'] = df['port'].apply(lambda x: int(hashlib.sha256(SALT + str(x).encode()).hexdigest(), 16) % 65536)
    
    # Run metrics
    print("Collision Rates:", calculate_collisions(df['IP Address'], df['anon_ip']))
    print("Entropy Change:", calculate_entropy(df['IP Address'], df['anon_ip']))
    print("Subnet Jaccard:", subnet_preservation(df['IP Address'], df['anon_ip']))
    print("Valid Ports (%):", port_validity(df['anon_port']))
    
    # Generate visualizations
    plot_subnet_heatmap(df['IP Address'].sample(100), df['anon_ip'].sample(100))
    
    # Calculate PUS
    pus = privacy_utility_score(
        H_delta=0.35,
        jaccard=0.82,
        collision_rate=0.15
    )
    print(f"Privacy-Utility Score: {pus:.2f}")
