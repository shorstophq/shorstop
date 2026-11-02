/* Fixture: OpenSSL in C, plus near-misses. */
#include <openssl/evp.h>
#include <openssl/rsa.h>

void run(void) {
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptInit_ex(c, EVP_des_ede3_cbc(), NULL, key, iv);
    EVP_DigestInit_ex(m, EVP_md5(), NULL);
    EVP_PKEY_CTX *pq = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);

    /* Near-misses: */
    EVP_DigestInit_ex(m, EVP_sha256(), NULL);
    int my_md5_count = 0;
}
