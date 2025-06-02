# Standard libraries
import string



def validate_input(input_string, input_type):
    """
    Validate the input string based on type, length, and allowed characters.

    Parameters:
        input_string (str): The string to validate.
        input_type (str): The type of input, either 'name' or 'path'.

    Returns:
        bool: True if input is valid, False if it exceeds length limits or contains invalid characters.
    """

    allowed_chars = string.ascii_letters + string.digits + '-_()'
    max_length = 50
    
    if input_type == 'name':
        allowed_chars = string.ascii_letters + string.digits + '-_() '
        max_length = 50
    elif input_type == 'path':
        allowed_chars = string.ascii_letters + string.digits + '-_/\\'
        max_length = 100
    
    if len(input_string) > max_length:
        print(f"Input exceeds maximum length of {max_length} characters.")
        return False
    elif any(char not in allowed_chars for char in input_string):
        print(f"Input contains invalid characters. Only the following characters are allowed: {allowed_chars}")
        return False
    else:
        return True
