import numpy as np
import hashlib

class DidaticMLKEM:
    def __init__(self):
        # Initialize any necessary parameters for the 
        self.n_coeficientes = 8
        self.q = 17
        self.k = 2
        self.eta = 1

    def sample_eta(self):
        return np.random.randint(-self.eta, self.eta + 1, size=self.n_coeficientes)

    def sample_eta_encaps(self, seed):
        stream = hashlib.shake_256(seed).digest(self.n_coeficientes)

        return np.array([(b % (2*self.eta+1)) - self.eta for b in stream])

    def descompact_mu(self, mu_bytes):
        mu_array = np.frombuffer(mu_bytes, dtype=np.uint8)
        bits = np.unpackbits(mu_array)
        mu_vec = bits * (self.q // 2)

        return mu_vec

    def KeyGen(self):
        # Generate a random secret key
        secret_key = np.array([self.sample_eta() for _ in range(self.k)])

        # Generate a random error vector
        error = np.array([self.sample_eta() for _ in range(self.k)])
        # Generate a random matrix A with entries in the range [0, q)
        A = np.random.randint(0, self.q, size=(self.k, self.k))
        
        # Compute the public key using the formula: public_key = A * secret_key + error (mod q)
        t = (A @ secret_key + error) % self.q

        pk_compress = t.tobytes() + A.tobytes()
        hash_pk = hashlib.shake_256(pk_compress).digest(32)

        public_key = (t, A, hash_pk)
      
        return public_key, secret_key

    def G(self, mu, hash_pk):
        # Concatenate mu and hash_pk
        concatenated = mu + hash_pk

        # Compute the hash of the concatenated value
        hashed_value = hashlib.sha3_512(concatenated).digest()
        K_bar = hashed_value[:32]
        r = hashed_value[32:]

        return K_bar, r

    def prf(seed, nonce, outlen):
        shake = hashlib.shake_256()
        shake.update(seed)
        shake.update(bytes([nonce]))
        
        return shake.digest(outlen)

    def Encapsulate(self, public_key):
        t, A, hash_pk = public_key

        # Generate a random byte mu
        mu = np.random.bytes(1)
        mu_vec = self.descompact_mu(mu)
        
        
        
        return ciphertext


if __name__ == "__main__":
    # Example usage of the functions in Didatic_ML_KEM.py

    # Create an instance of the DidaticMLKEM class
    kem = DidaticMLKEM()

    # Generate a public and secret key pair
    public_key, secret_key = kem.KeyGen()
    print("Public Key:", public_key)
    print("Secret Key:", secret_key)