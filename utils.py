def validate_port_range(port_range):
    parts = port_range.split('-')
    if len(parts) != 2:
        raise ValueError("Port range must be in the following format: 'start-end'.")
    start, end = int(parts[0]), int(parts[1])
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ValueError("Port numbers must be between 1 and 65535.")
    return start, end   
