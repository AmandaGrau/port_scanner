import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from scanner import scan_port, socket_scan, nmap_scan, parse_nmap_ports
from utils import validate_port_range


def run_socket_scan(host, port_range, output_box, scan_button, stop_button):
    """
    This function performs a custom socket scan on specified host and port range. 
    It handles updating the GUI output box with results and manages the button states during scanning.
    
    Args:
        host (str): Specified hostname or IP address to scan
        port_range (str): Port range in 'start-end' format (e.g., '20-443')
        output_box (tk.Text): GUI text widget for displaying scan results
        scan_button (tk.Button): Scan button to disable during scanning
        stop_button (tk.Button): Stop button to enable during scanning
    
    Returns:
        None: Results are displayed directly in the output_box
    """
    
    # Clear prior scan results from output box
    output_box.delete(1.0, tk.END)
    
    # Update button states: disable scan, enable, stop  
    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    
    try:
        # Perform socket scan using the scanner module
        open_ports = socket_scan(host, port_range)
        
        # Display results based on whether open ports were found
        if open_ports:
            for port in open_ports:
                output_box.insert(tk.END, f"Port {port} is open on Host {host}\n")
                
        else:
            # Inform the user that no open ports were found during scan
            output_box.insert(tk.END, f"No open ports found in range {port_range} on Host {host}\n")
            
    except Exception as e:
        # Handle and display any errors that occur during scanning
        output_box.insert(tk.END, f"Error occurred during socket scan: {e}\n")
    
    # Restore button states
    scan_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    
def run_nmap_scan(host, port_range, output_box, scan_button, stop_button):
    """
    This function uses the nmap command-line tool to perform port scanning.
    It displays raw nmap output and manages the GUI button states.
    
    Args:
        host (str): Specified hostname or IP address to scan
        port_range (str): Port range in 'start-end' format (e.g., '20-443')
        output_box (tk.Text): GUI text widget for displaying scan results
        scan_button (tk.Button): Scan button to disable during scanning
        stop_button (tk.Button): Stop button to enable during scanning
    
    Returns:
        None: Results are displayed directly in the output_box
    """
    
    # Clear prior scan results from output box    
    output_box.delete(1.0, tk.END)
    
    # Update button states: disable scan, enable, stop
    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    
    # Execute nmap scan and display results in output box
    nmap_output = nmap_scan(host, port_range)
    output_box.insert(tk.END, nmap_output)
    
    # Restore button states: enable scan, disable stop
    scan_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def on_scan_click(host_entry, port_entry, scan_method_var, output_box, scan_button, stop_button):
    """
    This function handles the scan button click event. 
    
    It validates user input and initiates the selected scanning method
    in a separate thread to prevent GUI freezing during long-running scans.
    
    Args:
        host_entry (tk.Entry): GUI entry field for specified host
        port_entry (tk.Entry): GUI entry field for port range
        scan_method_var (tk.StringVar): Variable for selected scan method
        output_box (tk.Text): GUI text box for displaying results
        scan_button (tk.Button): The scan button widget
        stop_button (tk.Button): The stop button widget
    
    Returns:
        None: Either starts a scan thread or displays validation errors
    """
    
    # Extract user input from GUI fields
    host = host_entry.get()
    port_range = port_entry.get()
    method = scan_method_var.get()
    
    try:
        # Validate port range format and values
        validate_port_range(port_range)
    
    except Exception as e:
        # Display validation error and exit if input is invalid
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, f"Invalid port range: {e}\n")
        return
    
    # Start selected scan method in a separate thread
    if method == "Socket":
        # Create and start thread for socket scanning
        t = Thread(target=run_socket_scan, args=(host, port_range, output_box, scan_button, stop_button))
        t.start()
        
    else:
        # Create and start thread for Nmap scanning
        t = Thread(target=run_nmap_scan, args=(host, port_range, output_box, scan_button, stop_button))
        t.start()
        

def on_stop_click(): 
    """
    This function handles the scan button click event.
    
    It simply updates the button states and does not actually stop a running scan.
        
    Returns:
        None: Updates button states only
    """
    
    # Reset button states (stop functionality not fully implemented)
    stop_button.config(state=tk.DISABLED)
    scan_button.config(state=tk.NORMAL)
    
    
# ========================================================= #
#                  GUI SETUP AND LAYOUT                     #
# ========================================================= #

# Create the main window    
root = tk.Tk()
root.title("Port Scanner GUI (Socket & Nmap)")

# Host input field
tk.Label(root, text="Host:").grid(row=0, column=0, padx=5, pady=5) 
host_entry = tk.Entry(root, width=30)
host_entry.grid(row=0, column=1)

# Port range input field
tk.Label(root, text="Port Range (e.g., 20-443):").grid(row=1, column=0, padx=5, pady=5)
port_entry = tk.Entry(root, width=30)
port_entry.grid(row=1, column=1)

# Scan method selection (dropdown) 
tk.Label(root, text="Scan Method:").grid(row=2, column=0, padx=5, pady=5)
scan_method_var = tk.StringVar(value="Socket")
scan_method_menu = tk.OptionMenu(root, scan_method_var, "Socket", "Nmap")
scan_method_menu.grid(row=2, column=1, padx=5, pady=5)

# Scan button (triggers scanning process)
scan_button = tk.Button(
    root, text="Scan", 
    command=lambda: on_scan_click(host_entry, port_entry, scan_method_var, output_box, scan_button, stop_button)
)
scan_button.grid(row=2, column=0, columnspan=2, pady=5)

# Stop button (currently only updates button state)
stop_button = tk.Button(
    root, text="Stop", 
   state=tk.DISABLED,    # Disabled until the scan process starts
   command=on_stop_click
)
stop_button.grid(row=2, column=2, pady=5)

# Scrollable output box to display results
output_box = scrolledtext.ScrolledText(root, width=50, height=15)
output_box.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Start the GUI event loop
root.mainloop()



    

    
