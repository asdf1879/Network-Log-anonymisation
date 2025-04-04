from urllib.parse import urlparse

def generalize_url(url_column):
    """
    Generalizes URLs by keeping only the domain and first-level path.
    
    Parameters:
    url_column (Series): Pandas Series of URLs.

    Returns:
    Series: Generalized URLs.
    """
    def simplify_url(url):
        try:
            parsed_url = urlparse(url)
            return f"{parsed_url.scheme}://{parsed_url.netloc}/{parsed_url.path.split('/')[1] if '/' in parsed_url.path else ''}"
        except:
            return "INVALID_URL"

    return url_column.apply(simplify_url)
