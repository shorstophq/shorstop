# Fixture: Ruby OpenSSL and Digest, plus near-misses.
require 'openssl'

key = OpenSSL::PKey::RSA.new(2048)
ec = OpenSSL::PKey::EC.generate('prime256v1')
cipher = OpenSSL::Cipher.new('aes-128-cbc') # generic AES rule
h = Digest::MD5.hexdigest(s)
s = OpenSSL::Digest::SHA1.new

# Near-misses:
ok = Digest::SHA256.hexdigest(s)
