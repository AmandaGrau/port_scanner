# Port Scanner (Socket & Nmap)
A simple Python GUI application to scan open ports on a host using socket and Nmap.

## Features

- **Socket Scan**: Scan ports using Python's socket library.
- **Nmap scan**: Scan ports using powerful Nmap tool (if installed).
- **GUI**: Easy-to-use graphical interface built with Tkinter.
- **Results Display**: View open ports in a scrollable output box.

## Requirements

- python 3.9+
- Tkinter (usually included with Python, but may require installation on some systems)
- Nmap (https://nmap.org/) (optional, only necessary if you want to use Nmap scan features)

---

### Installation

##
1. **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/port_scanner.git
    cd port_scanner
    ```
    
2. **Create Virtual Environment (Optional, but recommended)**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate
    ```

3. **Install Python dependencies**

    - There are no external Python dependencies required for this     
      application, as it uses built-in libraries.
    - ⚠️ If you plan to use Nmap scan , ensure it is installed on your system.

4. **Install Tkinter (if not already installed)**

    ```bash
    sudo apt-get install python3-tk  # On Debian/Ubuntu
    ```

    ```bash
    brew install python-tk  # On macOS
    ```

    ```bash
    choco install python-tk  # On Windows (Chocolatey)
    ``` 

5. **Install Nmap (optional, for Nmap scans)**

    ```bash
    sudo apt-get install nmap  # On Debian/Ubuntu
    ```

    ```bash
    brew install nmap  # On macOS
    ```

    ```bash
    choco install nmap  # On Windows (Chocolatey)
    ``` 

---

### Usage
##

### Run the application:

```bash
python3 main.py
```

### GUI Instructions:
- **Host:** Enter the hostname or IP address to scan.
- **Port Range:** Specify the range of ports to scan (e.g., `1-1000`).
- **Scan Method:** In the dropdown, choose between Socket Scan or Nmap Scan.
- **Scan:** Click the "Scan" button to begin scanning. Results will appear in the outbox below.
- **Stop:** Click the "Stop" button to halt the scan in progress.

### Run Tests:

A simple test script is included to verify the basic functionality of the socket scan and Nmap scan. You can run it using:

```bash
python3 scan_tests.py
```
##

<div align="center">

#### Created by Amanda Grau 🛠️

[![Email](https://img.shields.io/badge/Email-EA580C?style=for-the-badge&logo=gmail&logoColor=white)](mailto:agrau.dev@gmail.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-1E3A8A?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/AmandaGrau)
[![GitHub](https://img.shields.io/badge/GitHub-0F172A?style=for-the-badge&logo=github&logoColor=white)](https://github.com/AmandaGrau)
<!-- [![Portfolio](https://img.shields.io/badge/Portfolio-7C3AED?style=for-the-badge&logo=firefox&logoColor=white)](https://your-portfolio-link.com) -->

#### Thank you for checking out my project. Happy scanning!

##

<div align="center">

This project is licensed under the MIT License - see the [LICENSE](docs/LICENSE) file for details.