import numpy as np

def add_noise(column, epsilon=1.0):
    """
    Applies Laplace noise to a numerical column for differential privacy.
    
    Parameters:
    column (Series): Pandas Series of numerical values.
    epsilon (float): Privacy budget parameter.

    Returns:
    Series: Noisy data.
    """
    sensitivity = column.max() - column.min()
    scale = sensitivity / epsilon
    noise = np.random.laplace(0, scale, len(column))
    return column + noise
