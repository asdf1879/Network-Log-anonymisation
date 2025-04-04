def remove_low_entropy_columns(df, threshold=0.1):
    """
    Drops columns with low entropy (high re-identifiability).
    
    Parameters:
    df (DataFrame): Input DataFrame.
    threshold (float): Minimum entropy value required.

    Returns:
    DataFrame: Filtered DataFrame.
    """
    entropies = df.apply(lambda col: col.nunique() / len(col), axis=0)
    return df.loc[:, entropies > threshold]
