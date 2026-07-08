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

    def compact_mu(self, mu_vec):
        mu_centered = np.where(
            mu_vec > self.q//2,
            mu_vec - self.q,
            mu_vec
        )

        bits_rec = (
            np.abs(mu_centered)
            >
            self.q//4
        ).astype(np.uint8)

        # E por fim nessa etapa temos nosso mu recuperado em bytes
        mu_rec = np.packbits(bits_rec)

        return mu_rec.tobytes()

    def KeyGen(self):
        # Generate a random secret key
        s = np.array([self.sample_eta() for _ in range(self.k)])

        # Generate a random error vector
        error = np.array([self.sample_eta() for _ in range(self.k)])
        # Generate a random matrix A with entries in the range [0, q)
        A = np.random.randint(0, self.q, size=(self.k, self.k))
        
        # Compute the public key using the formula: public_key = A * s + error (mod q)
        t = (A @ s + error) % self.q

        pk_compress = t.tobytes() + A.tobytes()
        hash_pk = hashlib.shake_256(pk_compress).digest(32)

        public_key = (t, A, hash_pk)

        secret_key = {
            "s": s,
            "pk": public_key,
            "hash_pk": hash_pk,
            "z": np.random.bytes(32)
        }
      
        return public_key, secret_key

    @staticmethod
    def G(mu, hash_pk):
        # Concatenate mu and hash_pk
        concatenated = mu + hash_pk

        # Compute the hash of the concatenated value
        hashed_value = hashlib.sha3_512(concatenated).digest()
        K_bar = hashed_value[:32]
        r = hashed_value[32:]

        return K_bar, r

    def PRF(self,seed, nonce, outlen):
        shake = hashlib.shake_256()
        shake.update(seed)
        shake.update(bytes([nonce]))
        
        return shake.digest(outlen)

    def KDF(self, K_bar, ciphertext):
        c = ciphertext[0].tobytes() + ciphertext[1].tobytes()

        hash_c = hashlib.sha3_256(c).digest()
        
        K = hashlib.sha3_256(K_bar + hash_c).hexdigest()

        return K

    def seeds(self, r, n_vectors):
        return np.array([self.PRF(r, n, 32) for n in range(n_vectors)])

    def GenCiphertext(self, r, t, A, mu_vec):
        seeds = self.seeds(r, 5)  # Generate 5 seeds using the prf function
        
        random_secret = np.array([
            self.sample_eta_encaps(seeds[0]),
            self.sample_eta_encaps(seeds[1])
        ])

        error_u = np.array([
            self.sample_eta_encaps(seeds[2]),
            self.sample_eta_encaps(seeds[3])
        ])

        error_v = self.sample_eta_encaps(seeds[4])

        u = (A.T @ random_secret + error_u) % self.q
        v = (np.sum(t * random_secret, axis=0) + error_v + mu_vec) % self.q

        return u, v

    def Encapsulate(self, public_key):
        t, A, hash_pk = public_key

        # Generate a random byte mu
        mu = np.random.bytes(1)
        mu_vec = self.descompact_mu(mu)

        K_bar, r = self.G(mu, hash_pk)

        ciphertext = self.GenCiphertext(r, t, A, mu_vec)

        K = self.KDF(K_bar, ciphertext)

        return ciphertext, K

    def Decapsulate(self, ciphertext, secret_key):
        sk = secret_key
        t, A, hash_pk = sk["pk"]

        d = np.sum(sk["s"] * ciphertext[0], axis=0) % self.q
        mu_d = (ciphertext[1] - d) % self.q

        mu_rec = self.compact_mu(mu_d)

        K_bar_recovered, r_recovered = self.G(mu_rec, hash_pk)

        ciphertext_recomputed = self.GenCiphertext(r_recovered, t, A, self.descompact_mu(mu_rec))

        valid = (
            np.array_equal(ciphertext[0], ciphertext_recomputed[0])
            and
            np.array_equal(ciphertext[1], ciphertext_recomputed[1])
        )

        if valid:
            K = self.KDF(K_bar_recovered, ciphertext)

            return K, valid

        else:
            K = self.KDF(sk["z"], ciphertext)

            return K, valid

if __name__ == "__main__":
    # Example usage of the functions in Didatic_ML_KEM.py

    # Create an instance of the DidaticMLKEM class
    kem = DidaticMLKEM()

    # Generate a public and secret key pair
    public_key, secret_key = kem.KeyGen()
    print("Public Key:", public_key)
    print("Secret Key:", secret_key)

    # Encapsulate a key using the public key
    ciphertext, K = kem.Encapsulate(public_key)
    print("Cipher Text:", ciphertext)
    print("Shared Key:", K)

    # Decapsulate the key using the ciphertext and secret key
    K_recovered, valid = kem.Decapsulate(ciphertext, secret_key)
    print("Recovered Shared Key:", K_recovered)
    print("Valid:", valid)

    assert valid
    assert K == K_recovered
