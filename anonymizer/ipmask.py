import ipaddress

def generalize_ip(ip_column, subnet_mask=24):
    """
    Generalizes an IP address by masking the last octet(s) based on subnet.
    
    Parameters:
    ip_column (Series): Pandas Series of IP addresses.
    subnet_mask (int): The subnet mask (e.g., 24 for /24).
    
    Returns:
    Series: Generalized IPs.
    """
    def mask_ip(ip):
        try:
            network = ipaddress.IPv4Network(ip + f'/{subnet_mask}', strict=False)
            return str(network.network_address) + '/' + str(subnet_mask)
        except ValueError:
            return "INVALID_IP"

    return ip_column.apply(mask_ip)
