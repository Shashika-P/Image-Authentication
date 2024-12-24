# Image-Authentication
New software for image authentication

Step 01  -  Enter image path
Image pixel data will be taken as a 3D array.
Flat it out to a 1D array.
Create unique hash for this value.
Encrypt it using customer's private key and sign it using public key.
Embed the value(encrypted hash code, signature, timestamp if available) with the image EXIF data.

Step 02  -  Enter image for verification
Read EXIF data from image.
Generate a hash for the current image.
Decrypt the embedded data.
Check if the hash matches.
