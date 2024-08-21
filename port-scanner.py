import socket
from typing import List, Union

# Simplified dictionary of common ports and their services
common_ports = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5900: "vnc",
    8080: "http-proxy",
}

def get_open_ports(target: str, port_range: List[int], verbose: bool = False) -> Union[str, List[int]]:
    open_ports = []

    # Attempt to resolve the target as an IP address or hostname
    try:
        ip = socket.gethostbyname(target)
        resolved_target = target if target == ip else f"{target} ({ip})"
    except socket.gaierror:
        if any(c.isdigit() for c in target):  # Assume it's an IP address
            return "Error: Invalid IP address"
        else:  # Assume it's a hostname
            return "Error: Invalid hostname"
    
    # Scan the specified port range
    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)

    if verbose:
        output = f"Open ports for {resolved_target}\nPORT     SERVICE\n"
        for port in open_ports:
            service_name = common_ports.get(port, "unknown")
            output += f"{port:<9}{service_name}\n"
        return output.strip()

    return open_ports

# Example usage
print(get_open_ports("scanme.nmap.org", [20, 80], True))
