import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances

def laplace_noise(sensitivity, epsilon, size=1):
    """Generate Laplace noise based on given sensitivity and privacy parameter epsilon."""
    return np.random.laplace(loc=0, scale=sensitivity / epsilon, size=size)

def non_ip_diff_privacy(column, k=5, epsilon=1.0):
    """
    Applies Differentially Private Condensation to a single column.
    
    Parameters:
    - column: Pandas Series, the data to anonymize.
    - k: Minimum cluster size for k-anonymity.
    - epsilon: Privacy budget for Laplace noise.
    
    Returns:
    - A new Pandas Series with differentially private values.
    """
    
    column = column.values.reshape(-1, 1)  # Ensure correct shape for clustering
    n = len(column)

    # Step 3: Cluster values based on their numerical similarity
    kmeans = KMeans(n_clusters=min(k, n), n_init=10, random_state=42)
    clusters = kmeans.fit_predict(column)
    
    # Step 4: Sort clusters by size
    cluster_sizes = np.bincount(clusters)
    sorted_clusters = np.argsort(cluster_sizes)
    
    # Step 5: Balance clusters (Reassigning small clusters)
    for j in sorted_clusters:
        if cluster_sizes[j] < k:
            cluster_center = kmeans.cluster_centers_[j].reshape(1, -1)
            distances = pairwise_distances(column, cluster_center)
            closest_indices = np.argsort(distances.flatten())

            # Move records to Cj
            for idx in closest_indices:
                if clusters[idx] != j and cluster_sizes[clusters[idx]] > k:
                    cluster_sizes[clusters[idx]] -= 1
                    cluster_sizes[j] += 1
                    clusters[idx] = j
                    if cluster_sizes[j] >= k:
                        break
    
    # Step 6: Apply Differential Privacy
    for j in range(k):
        cluster_indices = np.where(clusters == j)[0]
        print(cluster_indices)
        if len(cluster_indices) > 0:
            mean_value = np.mean(column[cluster_indices])
            print(mean_value)
            for idx in cluster_indices:
                column[idx] = mean_value + laplace_noise(1, epsilon).item()

    return pd.Series(column.flatten())

# Testing
if __name__ == "__main__":
    sample = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    column = pd.Series(sample)
    k = 3
    epsilon = 1.0
    
    print("Original column:")
    print(column)
    print("\nApplying Differential Privacy:")
    print(non_ip_diff_privacy(column, k, epsilon))
