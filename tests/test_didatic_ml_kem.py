from Didatic_ML_KEM import DidaticMLKEM


def test_round_trip_key_exchange():
    kem = DidaticMLKEM()

    public_key, secret_key = kem.KeyGen()
    ciphertext, shared_key = kem.Encapsulate(public_key)
    recovered_key = kem.Decapsulate(ciphertext, secret_key)

    assert recovered_key == shared_key


def test_only_core_methods_are_public():
    kem = DidaticMLKEM()
    public_methods = {
        name for name in dir(kem)
        if callable(getattr(kem, name)) and not name.startswith("_")
    }

    assert {"KeyGen", "Encapsulate", "Decapsulate"} <= public_methods
    assert "sample_eta" not in public_methods
    assert "GenCiphertext" not in public_methods
