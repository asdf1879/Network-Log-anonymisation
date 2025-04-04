def enforce_l_diversity(df, group_cols, target_col, l):
    """
    Ensures l-diversity by filtering groups with at least `l` unique target values.
    
    Parameters:
    df (DataFrame): The input DataFrame.
    group_cols (list): List of column names defining the group.
    target_col (str): The sensitive attribute column.
    l (int): The minimum number of diverse values.

    Returns:
    DataFrame: Filtered DataFrame meeting l-diversity.
    """
    def check_diversity(group):
        return group if group[target_col].nunique() >= l else None

    return df.groupby(group_cols).apply(check_diversity).dropna()
