from datetime import datetime, timedelta
import pandas as pd

from datetime import datetime, timedelta
import pandas as pd
import random
import hashlib
def random_time_shift_column(timestamp_series: pd.Series, max_shift_hours=24) -> pd.Series:
    """
    Applies consistent dataset-wide time shift to preserve temporal order.
    Uses hash-based seeding for reproducible shifts.
    """
    # Generate single shift value for entire dataset
    seed = int(hashlib.sha256(timestamp_series.name.encode()).hexdigest(), 16) % 10**8
    random.seed(seed)
    dataset_shift = timedelta(seconds=random.randint(-max_shift_hours*3600, max_shift_hours*3600))

    def apply_shift(ts):
        try:
            dt = pd.to_datetime(ts, errors='coerce')
            if pd.isnull(dt):
                return ts
            return (dt + dataset_shift).strftime("%m/%d/%Y-%H:%M:%S.%f")[:-3]
        except:
            return ts

    return timestamp_series.map(apply_shift)

def perturb_time_column(timestamp_series: pd.Series, window_minutes=5) -> pd.Series:
    """
    Adds random perturbation within specified window while preserving 
    microsecond resolution format.
    """
    def add_perturbation(ts):
        try:
            dt = pd.to_datetime(ts, errors='coerce')
            if pd.isnull(dt):
                return ts
                
            jitter = random.randint(-window_minutes*60, window_minutes*60)
            perturbed = dt + timedelta(seconds=jitter)
            return perturbed.strftime("%m/%d/%Y-%H:%M:%S.%f")[:-3]
        except:
            return ts

    return timestamp_series.map(add_perturbation)

def bucketize_dates_column(timestamp_series: pd.Series, resolution='day') -> pd.Series:
    """
    Aggregates timestamps to broader time buckets:
    - 'day': YYYY-MM-DD 00:00:00
    - 'week': Monday of the week
    - 'month': First day of month
    """
    resolutions = {
        'day': lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0),
        'week': lambda dt: (dt - timedelta(days=dt.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0),
        'month': lambda dt: dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    }
    
    def bucketize(ts):
        try:
            dt = pd.to_datetime(ts, errors='coerce')
            if pd.isnull(dt) or resolution not in resolutions:
                return ts
            return resolutions[resolution](dt).strftime("%m/%d/%Y-%H:%M:%S.000")
        except:
            return ts

    return timestamp_series.map(bucketize)



def round_to_nearest_15_minutes_column(timestamp_series: pd.Series) -> pd.Series:
    """Rounds timestamps in a column to the nearest 15-minute mark."""
    def round_time(ts):
        try:
            dt = datetime.strptime(ts, "%m/%d/%Y-%H:%M:%S.%f")
            rounded_minute = (dt.minute // 15) * 15
            rounded_time = dt.replace(minute=rounded_minute, second=0, microsecond=0)
            return rounded_time.strftime("%m/%d/%Y-%H:%M:%S.000")
        except ValueError:
            return ts  # Keep as is if invalid
    
    return timestamp_series.map(round_time)


def order_preserving_adaptive_noise(timestamp_series: pd.Series, apply_global_offset=True) -> pd.Series:
    """
    Applies adaptive, order-preserving noise to sorted timestamps.
    Each timestamp is perturbed within bounds that preserve order.

    Parameters:
    - timestamp_series: A sorted pd.Series of timestamps in string format.
    - apply_global_offset: Whether to apply a global random offset to all timestamps.

    Returns:
    - A pd.Series of obfuscated timestamps as strings.
    """
    # Convert to datetime
    timestamps = pd.to_datetime(timestamp_series, errors='coerce')
    if timestamps.isnull().any():
        raise ValueError("Timestamp series contains invalid datetime entries.")

    perturbed = []

    for i in range(len(timestamps)):
        Ti = timestamps[i]

        if i == 0:
            delta = (timestamps[i + 1] - Ti) / 2
            low, high = timedelta(0), delta
        elif i == len(timestamps) - 1:
            delta = (Ti - timestamps[i - 1]) / 2
            low, high = -delta, timedelta(0)
        else:
            delta1 = (Ti - timestamps[i - 1]) / 2
            delta2 = (timestamps[i + 1] - Ti) / 2
            delta = min(delta1, delta2)
            low, high = -delta, delta

        noise = timedelta(seconds=random.uniform(low.total_seconds(), high.total_seconds()))
        perturbed.append(Ti + noise)

    if apply_global_offset:
        global_offset = timedelta(seconds=random.randint(-3600, 3600))  # ±1 hour
        perturbed = [ts + global_offset for ts in perturbed]

    return pd.Series([ts.strftime("%m/%d/%Y-%H:%M:%S.%f")[:-3] for ts in perturbed],
                     index=timestamp_series.index)
