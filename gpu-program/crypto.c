#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <cstdlib>

unsigned char key[16] = "0123456789abcdef";
unsigned char iv[16] = "deadbeefbeefdead";

int aes_128_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    putenv("OPENSSL_ia32cap=~0x200000200000000");
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    assert ((ctx = EVP_CIPHER_CTX_new()));

    assert (1 == EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv));

    assert (1 == EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));

    ciphertext_len = len;

    assert (1 == EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_128_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    putenv("OPENSSL_ia32cap=~0x200000200000000");
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    assert ((ctx = EVP_CIPHER_CTX_new()));

    assert (1 == EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv));

    assert (1 == EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len));

    plaintext_len = len;

    assert (1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len));

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void sha256(const unsigned char *data, size_t data_len) {
    unsigned char hash[256];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_len);
    SHA256_Final(hash, &sha256);
}
