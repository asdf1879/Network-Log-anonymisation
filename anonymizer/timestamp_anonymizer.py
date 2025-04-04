from datetime import datetime, timedelta
import pandas as pd

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
