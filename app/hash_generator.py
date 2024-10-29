import hashlib
def generate_hash_from_pixel_data(pixel_data):
    # Convert the 3D pixel data array to a 1D array
    flattened_array = pixel_data.flatten()

    # Convert the 1D array to bytes
    byte_data = flattened_array.tobytes()

    # Generate SHA-256 hash
    hash_object = hashlib.sha256(byte_data)

    # Return the hexadecimal representation of the hash
    return hash_object.hexdigest()