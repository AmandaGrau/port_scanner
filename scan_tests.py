from scanner import socket_scan, nmap_scan, parse_nmap_ports
import subprocess
import time

def run_test():
    print("==== Testing port range on localhost ====")
    open_ports = socket_scan("127.0.0.1", "20-443")
    print(f"... Show open ports in range (20-100): {open_ports}")
    
    print("\n==== Testing gateway/router ====")
    gateways = ['192.168.0.1', '192.168.1.1', '10.0.0.1']
    for gateway in gateways:
        if scan_port(gateway, 80):
            print(f"... Gateway found at {gateway}")
            router_ports = socket_scan(gateway, '80-85')
            print(f"... Gateway is reachable on port: {router_ports}")
            break
        
     # Test socket on external host
    print("\n==== External Host Test ====")
    print("Testing external host (google.com):")
    external_results = socket_scan("google.com", "80-85")
    print(f"... Socket scan results: {external_results}")
    
    # Test Nmap scan on external host
    print("Nmap scan on google.com:")
    nmap_output = nmap_scan("google.com", "80-85")
    nmap_results = parse_nmap_ports(nmap_output)
    print(f"... Nmap results: {nmap_results}")
    
    
    if "nmap is not installed" in nmap_output:
        print("... Install nmap to use nmap scan function.")
   
    
if __name__ == "__main__":
    run_test()