import socket                   
import subprocess               


# Function to scan single port on a given host
def scan_port(host, port):
    """
    This function scans a single port on a given host using socket connection.
    
    It attempts to establish a TCP connection to the given port range on the host. A successful connection indicates the port is open and accepting connections.
    
    Args:
        host (str): Specified hostname or IP address (e.g., "192.168.1.1", "google.com")
        port (int): Port number to scan (1-65535)
    
    Returns:
        bool: True if port is open and accepting connections, False otherwise
    """
    
    try:
        # Create TCP socket using IPv4
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
        
        # Set connection timeout to 1 second
        s.settimeout(1)    
        
        # Attempt to connect to host and port                                    
        s.connect((host, port))  
        
        # Return True indicating the port is open                              
        s.close()                                        
        return True                                         
    
    except Exception:  
        # Any exception (timeout, connection refused, etc.) means port is closed                                        
        return False
    

def socket_scan(host, port_range):
    """
    This function performs socket-based scanning across a specified port range.
    
    It iterates through each port in the range and tests connectivity using
    the scan_port function.
    
    Args:
        host (str): Specified hostname or IP address to scan
        port_range (str): Port range in "start-end" format (e.g., "20-443", "80-80")
    
    Returns:
        list: List of integers representing open port numbers found during scan
              Empty list if no open ports are discovered
    """
    
    # Parse the port range string into start and end integers
    start_port, end_port = map(int, port_range.split("-"))   
    
    # Initialize list to store open ports   
    open_ports = [] 
    
    # Iterate through each port in specified range (inclusive)                                            
    for port in range(start_port, end_port + 1): 
        # Test if the current port is open using socket connection
        if scan_port(host, port):
            # Add open port to results list                               
            open_ports.append(port) 
    # Return list of all open ports found                                       
    return open_ports                                        

# Function to scan range of ports using nmap
def nmap_scan(host, port_range):
    """
    This function executes nmap as a subprocess to perform advanced port scanning.
        
    Args:
        host (str): Specified hostname or IP address to scan
        port_range (str): Port range in nmap format (e.g., "20-443", "80,443", "1-1000")
    
    Returns:
        str: Raw nmap output containing scan results, or error message if scan fails
             The output includes port states, services, and scan statistics
    """
    
    try:
        # Construct nmap command with options:
        # --open: Show only open ports in output
        # -p: Specify port range to scan
        cmd = ["nmap", "--open", "-p", port_range, host]
        
        # Execute nmap command with output capture and error checking
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Return the standard output containing scan results
        return result.stdout
    
    except FileNotFoundError:
        # Handle case where nmap is not installed or not in PATH
        return "nmap is not installed. Please install nmap to scan with this function."
    # Handle nmap execution errors (invalid arguments, network issues, etc.)
    
    except subprocess.CalledProcessError as e:
        # Handle nmap execution errors (invalid arguments, network issues, etc.)
        return f"A subprocess error occurred while running nmap: {e.stderr}"
    
    # Handle other unexpected errors during nmap scanning
    except Exception as e:
        return f"An unexpected error occurred while running nmap: {str(e)}"
    

def parse_nmap_ports(nmap_output):
    """
    This function extracts open port numbers from nmap scan output.
    
    It parses raw text output from nmap and extracts
    just the port numbers that were found to be open. It handles
    various nmap output formats and error conditions.
    
    Args:
        nmap_output (str): Raw nmap output text from nmap_scan function
    
    Returns:
        list: List of integers representing open port numbers found in Nmap output
        Empty list indicates no open ports were found or the output contains errors
    """
    
    # Check for error conditions in nmap output
    if "nmap is not installed" in nmap_output or "error occurred" in nmap_output:
        return []
    
    # Initialize list to store extracted port numbers
    open_ports = []
    
    # Split output into seperate lines 
    lines = nmap_output.split('\n')
    
    # Process each line looking for port information
    for line in lines:
        
        # Look for lines containing "open" status
        if "open" in line:
            try:
                
               # Extract port number from "PORT/tcp open service"
               # Split by '/'
               # Take the first part, then convert to integer    
               port = int(line.split('/')[0].strip())
               open_ports.append(port)
               
            # Skip lines that don't have valid port number format
            except (ValueError):
                continue
    # Return list of parsed open port numbers
    return open_ports

