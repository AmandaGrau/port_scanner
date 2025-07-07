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



