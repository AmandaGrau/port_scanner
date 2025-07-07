import socket                   
import subprocess               
from datetime import datetime   

# Function to scan single port on a given host
def scan_port(host, port):
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
        s.settimeout(1)                                        
        s.connect((host, port))                                
        s.close()                                        
        return True                                         
    
    except Exception:                                          
        return False
    
# Function to scan range of ports on given host with socket
def socket_scan(host, port_range):
    start_port, end_port = map(int, port_range.split("-"))      
    open_ports = []                                             
    for port in range(start_port, end_port + 1):                
        if scan_port(host, port):                               
            open_ports.append(port)                                        
    return open_ports                                        

# Function to scan range of ports using nmap
def nmap_scan(host, port_range):
    
    try:
        cmd = ["nmap", "--open", "-p", port_range, host]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except FileNotFoundError:
        return "nmap is not installed. Please install nmap to scan with this function."
    except subprocess.CalledProcessError as e:
        return f"A subprocess error occurred while running nmap: {e.stderr}"
    except Exception as e:
        return f"An unexpected error occurred while running nmap: {str(e)}"
    
# Function to extract open port numbers from nmap output
def parse_nmap_ports(nmap_output):
    
    if "nmap is not installed" in nmap_output or "error occurred" in nmap_output:
        return []
    
    open_ports = []
    lines = nmap_output.split('\n')
    for line in lines:
        if "open" in line:
            try:
               port = int(line.split('/')[0].strip())
               open_ports.append(port)
            except (ValueError):
                continue
    return open_ports

