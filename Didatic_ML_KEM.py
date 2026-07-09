import hashlib
from typing import Any, Dict, Tuple

import numpy as np


class DidaticMLKEM:
    """A didactic, simplified implementation of a Kyber-like key encapsulation flow."""

    def __init__(self, n_coefficients: int = 8, q: int = 17, k: int = 2, eta: int = 1) -> None:
        """Initialize the toy parameters used by the notebook example."""
        if n_coefficients <= 0:
            raise ValueError("n_coefficients must be a positive integer")
        if q <= 0:
            raise ValueError("q must be a positive integer")
        if k <= 0:
            raise ValueError("k must be a positive integer")
        if eta < 0:
            raise ValueError("eta must be non-negative")

        self.n_coefficients = n_coefficients
        self.q = q
        self.k = k
        self.eta = eta

    def KeyGen(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Generate a toy public/secret key pair following the notebook flow."""
        # The secret vector s is the private ingredient used to derive the public value t.
        s = np.array([self._sample_eta() for _ in range(self.k)], dtype=np.int64)

        # The error term is the small noise that makes the toy LWE-style problem hard.
        error = np.array([self._sample_eta() for _ in range(self.k)], dtype=np.int64)

        # A is a random matrix that acts as the public basis of the learning problem.
        A = np.random.randint(0, self.q, size=(self.k, self.k), dtype=np.int64)

        # This mirrors the notebook formula: t = A * s + e (mod q).
        t = (A @ s + error) % self.q

        hash_pk = self._hash_public_key(t, A)

        public_key = {
            "t": t,
            "A": A,
            "hash_pk": hash_pk,
        }

        secret_key = {
            "s": s,
            "pk": public_key,
            "hash_pk": hash_pk,
            "z": np.random.bytes(32),
        }

        return public_key, secret_key

    def Encapsulate(self, public_key: Dict[str, Any]) -> Tuple[Tuple[np.ndarray, np.ndarray], bytes]:
        """Encapsulate a random message into a ciphertext and derive a shared key."""
        self._validate_public_key(public_key)

        # Generate a one-byte message-like value and expand it into a small vector.
        mu = np.random.bytes(1)
        mu_vec = self._descompact_mu(mu)

        # The notebook uses G(mu, H(pk)) to derive the intermediate seed and randomness.
        k_bar, r = self._hash_g(mu, public_key["hash_pk"])

        ciphertext = self._generate_ciphertext(r, public_key["t"], public_key["A"], mu_vec)
        shared_key = self._kdf(k_bar, ciphertext)

        return ciphertext, shared_key

    def Decapsulate(self, ciphertext: Tuple[np.ndarray, np.ndarray], secret_key: Dict[str, Any]) -> bytes:
        """Recover a shared key from a ciphertext using the secret key."""
        self._validate_ciphertext(ciphertext)
        self._validate_secret_key(secret_key)

        # Recover the approximate message vector from the ciphertext.
        d = np.sum(secret_key["s"] * ciphertext[0], axis=0) % self.q
        mu_d = (ciphertext[1] - d) % self.q
        mu_rec = self._compact_mu(mu_d)

        # Recreate the same intermediate values to verify that the ciphertext is valid.
        k_bar_recovered, r_recovered = self._hash_g(mu_rec, secret_key["pk"]["hash_pk"])
        ciphertext_recomputed = self._generate_ciphertext(
            r_recovered,
            secret_key["pk"]["t"],
            secret_key["pk"]["A"],
            self._descompact_mu(mu_rec),
        )

        valid = (
            np.array_equal(ciphertext[0], ciphertext_recomputed[0])
            and np.array_equal(ciphertext[1], ciphertext_recomputed[1])
        )

        if valid:
            return self._kdf(k_bar_recovered, ciphertext)

        # In a full Kyber implementation this would be a structured fallback; here we keep it simple.
        return self._kdf(secret_key["z"], ciphertext)

    def _sample_eta(self, size: int | None = None) -> np.ndarray:
        """Draw small integer values in the range [-eta, eta]."""
        if size is None:
            size = self.n_coefficients
        return np.random.randint(-self.eta, self.eta + 1, size=size, dtype=np.int64)

    def _sample_eta_encaps(self, seed: bytes) -> np.ndarray:
        """Expand a seed into a small vector using SHAKE-256, as in the notebook."""
        stream = hashlib.shake_256(seed).digest(self.n_coefficients)
        return np.array([(b % (2 * self.eta + 1)) - self.eta for b in stream], dtype=np.int64)

    def _descompact_mu(self, mu_bytes: bytes) -> np.ndarray:
        """Convert a byte value into a simple vector of bits scaled by q/2."""
        mu_array = np.frombuffer(mu_bytes, dtype=np.uint8)
        bits = np.unpackbits(mu_array)
        return bits * (self.q // 2)

    def _compact_mu(self, mu_vec: np.ndarray) -> bytes:
        """Convert a recovered message vector back into bytes with a simple threshold rule."""
        mu_centered = np.where(mu_vec > self.q // 2, mu_vec - self.q, mu_vec)
        bits_rec = (np.abs(mu_centered) > self.q // 4).astype(np.uint8)
        mu_rec = np.packbits(bits_rec)
        return mu_rec.tobytes()

    def _hash_public_key(self, t: np.ndarray, A: np.ndarray) -> bytes:
        """Create a compact digest of the public components for later derivation steps."""
        payload = t.tobytes() + A.tobytes()
        return hashlib.sha3_256(payload).digest()

    def _hash_g(self, mu: bytes, hash_pk: bytes) -> Tuple[bytes, bytes]:
        """Derive the intermediate key material K_bar and the randomness seed r."""
        concatenated = mu + hash_pk
        hashed_value = hashlib.sha3_512(concatenated).digest()
        return hashed_value[:32], hashed_value[32:]

    def _prf(self, seed: bytes, nonce: int, outlen: int) -> bytes:
        """A lightweight pseudorandom function used to derive seeds for the toy ciphertext."""
        shake = hashlib.shake_256()
        shake.update(seed)
        shake.update(bytes([nonce]))
        return shake.digest(outlen)

    def _kdf(self, key_material: bytes, ciphertext: Tuple[np.ndarray, np.ndarray]) -> bytes:
        """Derive the shared key from the intermediate key material and the ciphertext."""
        c = ciphertext[0].tobytes() + ciphertext[1].tobytes()
        hash_c = hashlib.sha3_256(c).digest()
        return hashlib.sha3_256(key_material + hash_c).digest()

    def _derive_seeds(self, r: bytes, n_vectors: int) -> np.ndarray:
        """Create a small set of deterministic seeds from the randomness input."""
        return np.array([self._prf(r, n, 32) for n in range(n_vectors)], dtype=object)

    def _generate_ciphertext(
        self,
        r: bytes,
        t: np.ndarray,
        A: np.ndarray,
        mu_vec: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Create u and v from the toy Kyber-style encapsulation formulas."""
        seeds = self._derive_seeds(r, 5)

        random_secret = np.array([
            self._sample_eta_encaps(seeds[0]),
            self._sample_eta_encaps(seeds[1]),
        ], dtype=np.int64)

        error_u = np.array([
            self._sample_eta_encaps(seeds[2]),
            self._sample_eta_encaps(seeds[3]),
        ], dtype=np.int64)

        error_v = self._sample_eta_encaps(seeds[4])

        u = (A.T @ random_secret + error_u) % self.q
        v = (np.sum(t * random_secret, axis=0) + error_v + mu_vec) % self.q
        return u, v

    def _validate_public_key(self, public_key: Dict[str, Any]) -> None:
        """Check that the public key contains the expected fields."""
        required = {"t", "A", "hash_pk"}
        missing = required.difference(public_key.keys())
        if missing:
            raise ValueError(f"Public key is missing required fields: {sorted(missing)}")

    def _validate_secret_key(self, secret_key: Dict[str, Any]) -> None:
        """Check that the secret key contains the expected fields."""
        required = {"s", "pk", "hash_pk", "z"}
        missing = required.difference(secret_key.keys())
        if missing:
            raise ValueError(f"Secret key is missing required fields: {sorted(missing)}")

    def _validate_ciphertext(self, ciphertext: Tuple[np.ndarray, np.ndarray]) -> None:
        """Ensure that the ciphertext has the expected shape and components."""
        if not isinstance(ciphertext, tuple) or len(ciphertext) != 2:
            raise ValueError("Ciphertext must be a tuple containing two arrays")

        u, v = ciphertext
        if not isinstance(u, np.ndarray) or not isinstance(v, np.ndarray):
            raise ValueError("Ciphertext components must be numpy arrays")


if __name__ == "__main__":
    kem = DidaticMLKEM()

    public_key, secret_key = kem.KeyGen()
    print("Public Key:", public_key)
    print()
    print("Secret Key:", secret_key)
    print()

    ciphertext, shared_key = kem.Encapsulate(public_key)
    print("Cipher Text:", ciphertext)
    print()
    print("Shared Key:", shared_key.hex())

    recovered_key = kem.Decapsulate(ciphertext, secret_key)
    print("Recovered Shared Key:", recovered_key.hex())
