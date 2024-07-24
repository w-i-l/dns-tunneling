import ipaddress

def convert_bytes_to_int(data: bytes) -> int:
    '''
    Returns the integer representation of the bytes with big endian byte order
    '''
    return int.from_bytes(data, byteorder='big')

def verify_dns_server_ip(ip: str) -> bool:
    '''
    Verifies if the given IP address is a valid IP address
    '''
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False