# Fixture: Python crypto, plus near-misses that must not match.
import hashlib
from Crypto.PublicKey import RSA
from Cryptodome.PublicKey import DSA, ECC
from Crypto.Cipher import AES, DES3, ARC4
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import oqs

key = RSA.generate(2048)
cipher = AES.new(key, AES.MODE_ECB)
gcm = AES.new(key, AES.MODE_GCM, nonce=n)
legacy = AES.new(key, AES.MODE_OPENPGP)  # mode not in the closed set: Mode stays empty
digest = hashlib.md5(data).hexdigest()
h = hashlib.new("sha1")
priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
priv2 = rsa.generate_private_key(  # key size on the next line: unknown
    public_exponent=65537, key_size=4096)
eck = ec.generate_private_key(ec.SECP256R1())
params = dh.generate_parameters(generator=2, key_size=2048)
c = Cipher(algorithms.TripleDES(k), modes.ECB())  # 3DES, so not the AES-ECB rule
c2 = Cipher(algorithms.AES(k), modes.ECB())
with oqs.KeyEncapsulation("ML-KEM-768") as kem:  # also generic-mlkem-name
    pass
# cipher = AES.new(key, AES.MODE_CBC)  -- comments are matched too

# Near-misses: none of these lines may produce a finding.
ok = hashlib.sha256(data)
md5sum = compute_checksum(path)
text = 'KeyPairGenerator.getInstance("RSA")'  # Java rule: wrong language
bits = rsa_key_size
