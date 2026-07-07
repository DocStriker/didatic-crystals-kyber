import numpy as np
import hashlib

if __name__ == "__main__":
    # Example usage of the functions in Didatic_ML_KEM.py
    # Generate a random message
    message = np.random.randint(0, 256, size=32, dtype=np.uint8)
    
    # Hash the message using SHA-256
    hash_object = hashlib.sha256(message.tobytes())
    hash_digest = hash_object.hexdigest()
    
    print("Random Message:", message)
    print("SHA-256 Hash:", hash_digest)