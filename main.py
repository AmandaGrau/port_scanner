import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from scanner import scan_port, socket_scan, nmap_scan, parse_nmap_ports
from utils import validate_port_range

def run_socket_scan(host, port_range, output_box, scan_button, stop_button):
    output_box.delete(1.0, tk.END)
    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    try:
        open_ports = socket_scan(host, port_range)
        if open_ports:
            for port in open_ports:
                output_box.insert(tk.END, f"Port {port} is open on Host {host}\n")
        else:
            output_box.insert(tk.END, f"No open ports found in range {port_range} on Host {host}\n")
    except Exception as e:
        output_box.insert(tk.END, f"Error occurred during socket scan: {e}\n")
    scan_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    
def run_nmap_scan(host, port_range, output_box, scan_button, stop_button):
    output_box.delete(1.0, tk.END)
    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    nmap_output = nmap_scan(host, port_range)
    output_box.insert(tk.END, nmap_output)
    scan_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def on_scan_click(host_entry, port_entry, scan_method_var, output_box, scan_button, stop_button):
    host = host_entry.get()
    port_range = port_entry.get()
    method = scan_method_var.get()
    
    try:
        validate_port_range(port_range)
    
    except Exception as e:
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, f"Invalid port range: {e}\n")
        return
    
    if method == "Socket":
        t = Thread(target=run_socket_scan, args=(host, port_range, output_box, scan_button, stop_button))
        t.start()
    else:
        t = Thread(target=run_nmap_scan, args=(host, port_range, output_box, scan_button, stop_button))
        t.start()
        
# Disable the stop button
def on_stop_click(): 
    stop_button.config(state=tk.DISABLED)
    scan_button.config(state=tk.NORMAL)
    
root = tk.Tk()
root.title("Port Scanner GUI (Socket & Nmap)")

tk.Label(root, text="Host:").grid(row=0, column=0, padx=5, pady=5) 
host_entry = tk.Entry(root, width=30)
host_entry.grid(row=0, column=1)

tk.Label(root, text="Port Range (e.g., 20-443):").grid(row=1, column=0, padx=5, pady=5)
port_entry = tk.Entry(root, width=30)
port_entry.grid(row=1, column=1)

tk.Label(root, text="Scan Method:").grid(row=2, column=0, padx=5, pady=5)
scan_method_var = tk.StringVar(value="Socket")
scan_method_menu = tk.OptionMenu(root, scan_method_var, "Socket", "Nmap")
scan_method_menu.grid(row=2, column=1, padx=5, pady=5)

scan_button = tk.Button(
    root, text="Scan", 
    command=lambda: on_scan_click(host_entry, port_entry, scan_method_var, output_box, scan_button, stop_button)
)
scan_button.grid(row=2, column=0, columnspan=2, pady=5)

stop_button = tk.Button(
    root, text="Stop", 
   state=tk.DISABLED,
   command=on_stop_click
)
stop_button.grid(row=2, column=2, pady=5)

output_box = scrolledtext.ScrolledText(root, width=50, height=15)
output_box.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()



    

    
