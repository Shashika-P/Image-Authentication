from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Step 1: Generate RSA Keys for User A (sender) and User B (receiver)
private_key_a = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key_a = private_key_a.public_key()

private_key_b = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key_b = private_key_b.public_key()

message = b"This is a message to sign, #111111111111111111111111111111111111111111111111111111"
is_Signature_Valid = False

# Step 2: User A Encrypts the Message with User B's Public Key
def encrypt_message(public_key_b, message):
  encrypted_message = public_key_b.encrypt(
      message,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return encrypted_message

# Step 3: User A Signs the Encrypted Message with their Private Key
def sign_message(private_key_a, encrypted_message):
  signature = private_key_a.sign(
      encrypted_message,
      padding.PSS(
          mgf=padding.MGF1(hashes.SHA256()),
          salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
  )
  return signature

print('private_key_a :', private_key_a, '\n\npublic_key_a :', public_key_a, '\n\nprivate_key_b :', private_key_b, '\n\npublic_key_b :', public_key_b)


# Step 4: User B Decrypts the Encrypted Message with their Private Key
def decrypt_message(private_key_b, encrypted_message):
  decrypted_message = private_key_b.decrypt(
      encrypted_message,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return decrypted_message

# Step 5: User B Verifies the Signature with User A's Public Key
def check_message_signature(signature, encrypted_message):
  try:
      public_key_a.verify(
          signature,
          encrypted_message,
          padding.PSS(
              mgf=padding.MGF1(hashes.SHA256()),
              salt_length=padding.PSS.MAX_LENGTH
          ),
          hashes.SHA256()
      )
      print("\nSignature is valid. Message integrity confirmed.")
      is_Signature_Valid = True
  except InvalidSignature:
      is_Signature_Valid = False
      print("\nSignature is invalid. Message has been tampered with.")
  return is_Signature_Valid

encrypted_message = encrypt_message(public_key_b, message)
signature = sign_message(private_key_a, encrypted_message)
is_Signature_Valid = check_message_signature(signature, encrypted_message)

if (is_Signature_Valid == True):
  decrypt_message = decrypt_message(private_key_b, encrypted_message)
  print('\ndecrypted message :', decrypt_message.decode())
elif (is_Signature_Valid == False):
  print('No further calculations will be done.')