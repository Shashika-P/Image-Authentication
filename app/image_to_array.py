from PIL import Image
import numpy as np

def image_to_array(image_path):
    """
    Convert an image to a NumPy array.

    Args:
        image_path (str): The path to the image file.

    Returns:
        np.ndarray: The image represented as a NumPy array.
    """
    image = Image.open(image_path)  # Open the image file

    # Convert the image to raw pixel values
    pixel_data = np.array(image)

    # Calculate number of pixels
    height, width, channels = pixel_data.shape  # Unpack the shape of the array
    total_pixels = height * width  # Calculate total number of pixels

    # Print the total number of pixels
    print(f"Total number of pixels: {total_pixels}")
    return pixel_data