from scanner import scan_port, socket_scan
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
            print(f"... Router found at {gateway}")
            router_ports = socket_scan(gateway, '80-85')
            print(f"... Router reachable on port: {router_ports}")
            break
        
    print("\n==== Testing scan performance ====")
    start_time = time.time()
    results = socket_scan('127.0.0.1', '20-100')

    
if __name__ == "__main__":
    run_test()