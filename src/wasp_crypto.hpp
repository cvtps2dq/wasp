#pragma once

// Standard Includes
#include <memory>
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <span>
#include <iostream>

// OpenSSL Includes
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h> // <--- CRITICAL: Defines BUF_MEM

#include "wasp_defs.hpp"

namespace wasp::crypto {

    // RAII for OpenSSL pointers
    template<typename T>
    using SslPtr = std::unique_ptr<T, void(*)(T*)>;

    // 1. Random Generation
    inline void random_bytes(std::span<uint8_t> out) {
        if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
            throw std::runtime_error("OpenSSL RAND_bytes failed");
        }
    }

    // 2. X25519 Key Exchange
    struct KeyPair {
        ByteBuffer pub_key;
        SslPtr<EVP_PKEY> pkey{nullptr, EVP_PKEY_free};
    };

    inline KeyPair generate_x25519() {
        SslPtr<EVP_PKEY_CTX> ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free};
        EVP_PKEY* pkey = nullptr;

        EVP_PKEY_keygen_init(ctx.get());
        EVP_PKEY_keygen(ctx.get(), &pkey);

        size_t len = 0;
        EVP_PKEY_get_raw_public_key(pkey, nullptr, &len);
        ByteBuffer pub_bytes(len);
        EVP_PKEY_get_raw_public_key(pkey, pub_bytes.data(), &len);

        return { std::move(pub_bytes), SslPtr<EVP_PKEY>{pkey, EVP_PKEY_free} };
    }

    inline ByteBuffer derive_secret(EVP_PKEY* local_priv, ByteSpan peer_pub_bytes) {
        SslPtr<EVP_PKEY> peer_key{
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub_bytes.data(), peer_pub_bytes.size()),
            EVP_PKEY_free
        };

        if (!peer_key) throw std::runtime_error("Invalid peer key");

        SslPtr<EVP_PKEY_CTX> ctx{EVP_PKEY_CTX_new(local_priv, nullptr), EVP_PKEY_CTX_free};
        EVP_PKEY_derive_init(ctx.get());
        EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get());

        size_t secret_len;
        EVP_PKEY_derive(ctx.get(), nullptr, &secret_len);
        ByteBuffer secret(secret_len);
        EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len);

        return secret;
    }

    // 3. HKDF (Key Derivation)
    inline ByteBuffer hkdf_derive(ByteSpan secret, ByteSpan salt, std::string_view info) {
        SslPtr<EVP_KDF> kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free};
        SslPtr<EVP_KDF_CTX> kctx{EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free};

        OSSL_PARAM params[5];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0);
        params[1] = OSSL_PARAM_construct_octet_string("key", (void*)secret.data(), secret.size());
        params[2] = OSSL_PARAM_construct_octet_string("salt", (void*)salt.data(), salt.size());
        params[3] = OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size());
        params[4] = OSSL_PARAM_construct_end();

        ByteBuffer out_key(KEY_SIZE);
        if (EVP_KDF_derive(kctx.get(), out_key.data(), KEY_SIZE, params) <= 0) {
             throw std::runtime_error("HKDF failed");
        }
        return out_key;
    }

    // 4. AES-256-GCM Encrypt
    inline ByteBuffer aes_gcm_encrypt(ByteSpan key, ByteSpan iv, ByteSpan plaintext) {
        SslPtr<EVP_CIPHER_CTX> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data());

        ByteBuffer out(plaintext.size() + TAG_SIZE);
        int outlen;

        EVP_EncryptUpdate(ctx.get(), out.data(), &outlen, plaintext.data(), static_cast<int>(plaintext.size()));
        int final_len;
        EVP_EncryptFinal_ex(ctx.get(), out.data() + outlen, &final_len);

        ByteBuffer tag(TAG_SIZE);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data());

        std::memcpy(out.data() + outlen, tag.data(), TAG_SIZE);
        return out;
    }

    // 5. AES-256-GCM Decrypt
    inline ByteBuffer aes_gcm_decrypt(ByteSpan key, ByteSpan iv, ByteSpan ciphertext_with_tag) {
        if (ciphertext_with_tag.size() < TAG_SIZE) throw std::runtime_error("Data too short");

        size_t data_len = ciphertext_with_tag.size() - TAG_SIZE;
        ByteSpan ciphertext = ciphertext_with_tag.subspan(0, data_len);
        ByteSpan tag = ciphertext_with_tag.subspan(data_len, TAG_SIZE);

        SslPtr<EVP_CIPHER_CTX> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data());

        ByteBuffer plaintext(data_len);
        int outlen;

        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, ciphertext.data(), static_cast<int>(ciphertext.size()));

        // Set expected tag
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag.data());

        int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen);

        if (ret > 0) return plaintext;
        throw std::runtime_error("Auth Tag Mismatch");
    }

    // 6. Base64 Helpers
    inline std::string base64_encode(ByteSpan input) {
        SslPtr<BIO> b64{BIO_new(BIO_f_base64()), BIO_free_all};
        BIO* bmem = BIO_new(BIO_s_mem());
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL); // No newlines
        BIO_push(b64.get(), bmem);

        BIO_write(b64.get(), input.data(), static_cast<int>(input.size()));
        BIO_flush(b64.get());

        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64.get(), &bptr);
        return {bptr->data, bptr->length};
    }

    inline ByteBuffer base64_decode(std::string_view input) {
        size_t len = input.length();
        size_t padding = 0;
        if (len > 0 && input[len-1] == '=') padding++;
        if (len > 1 && input[len-2] == '=') padding++;

        size_t out_len = (len * 3) / 4 - padding;
        ByteBuffer out(out_len);

        SslPtr<BIO> b64{BIO_new(BIO_f_base64()), BIO_free_all};
        BIO* bmem = BIO_new_mem_buf(input.data(), static_cast<int>(input.length()));
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64.get(), bmem);

        int ret = BIO_read(b64.get(), out.data(), static_cast<int>(input.length()));
        if (ret < 0) throw std::runtime_error("Base64 decode failed");

        out.resize(ret);
        return out;
    }
}