import image_to_array
import hash_generator
import image_cryptography
import image_meta_data

def convert_image(image_path):
    # Call the function
    pixel_data = image_to_array.image_to_array(image_path)
    hash_code = hash_generator.generate_hash_from_pixel_data(pixel_data)
    print('\nHash code :', hash_code)

    # Generate keys
    private_key, public_key = image_cryptography.generate_keys()
    print('private_key and public_key have been generated')
    # Message to encrypt
    message = hash_code

    # Encrypt the message
    encrypted = image_cryptography.encrypt_message(public_key, message)
    print(f"Encrypted message: {encrypted}")

    #write custom meta data
    image_meta_data.write_custom_metadata(image_path, "XMP:UserComment", encrypted.hex())
    result = image_meta_data.read_custom_metadata(image_path, "XMP:UserComment")
    print("custom meta data :", result)
    result2 = image_meta_data.read_all_metadata(image_path)
    print("all meta data :", result2)