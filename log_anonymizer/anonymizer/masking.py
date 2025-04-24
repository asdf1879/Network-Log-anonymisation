def mask_data(column, mask_char="X", visible_chars=3):
    """
    Masks a column's values by replacing characters except for a few visible ones.
    
    Parameters:
    column (Series): Pandas Series of values to mask.
    mask_char (str): The character to use for masking.
    visible_chars (int): Number of visible characters at the start.

    Returns:
    Series: Masked column values.
    """
    return column.apply(lambda x: x[:visible_chars] + mask_char * (len(x) - visible_chars))
