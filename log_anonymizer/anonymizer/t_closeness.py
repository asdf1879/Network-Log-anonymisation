from scipy.stats import wasserstein_distance

def enforce_t_closeness(df, group_cols, sensitive_col, t):
    """
    Ensures t-closeness by keeping groups where the sensitive attribute distribution is close to global distribution.
    
    Parameters:
    df (DataFrame): The input DataFrame.
    group_cols (list): List of column names defining the group.
    sensitive_col (str): The sensitive attribute column.
    t (float): The maximum allowed distance.

    Returns:
    DataFrame: Filtered DataFrame meeting t-closeness.
    """
    global_dist = df[sensitive_col].value_counts(normalize=True)

    def check_closeness(group):
        group_dist = group[sensitive_col].value_counts(normalize=True)
        distance = wasserstein_distance(global_dist, group_dist)
        return group if distance <= t else None

    return df.groupby(group_cols).apply(check_closeness).dropna()
