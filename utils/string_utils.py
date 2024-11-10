


# Removes duplicates from a comma-separated string and preserves order.
def remove_duplicates(value):
    if value:
        unique_values = list(dict.fromkeys(value.split(',')))  # Remove duplicates while preserving order
        return ','.join(unique_values)
    return value