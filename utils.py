def validate_port_range(port_range):
    """
    This function validates and parses a port range string for network scanning.
    
    It ensures port range input follows correct format and contains valid port numbers 
    within the acceptable range for TCP/UDP networking to prevent scanning errors.
    
    Args:
        port_range (str): Port range (str) in "start-end" format 
                          (e.g., "80-443", "1-65535", "22-22")
                             
    Returns:
        tuple: (start_port, end_port) as integers if validation passes
               Both values will be between 1 and 65535 inclusive
    
    Raises:
        ValueError: If any of the following conditions are met:
                   - Format is not "number-number"
                   - Port numbers are not integers
                   - Port numbers are outside valid range (1-65535)
                   - Start port is greater than end port
                   - Contains invalid characters or whitespace
    """
    
    # Split the input string on dash separator
    parts = port_range.split('-')
    
    # Validate there are two parts for the port range (start and end)
    if len(parts) != 2:
        raise ValueError("Port range must be in the following format: 'start-end'.")
    
    # Convert string input parts to integers 
    # Will raise ValueError if string conversion fails 
    start, end = int(parts[0]), int(parts[1])
    
    # Validate all port number conditions are met for valid range:
    # Both parts in valid range (1-65535)
    # Start port is not greater than end port
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ValueError("Port numbers must be between 1 and 65535.")
    
    # Return validated port range as a tuple of integers
    return start, end   
