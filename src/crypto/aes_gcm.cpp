// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "aes_gcm.hpp"
#include <memory>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace Crypto {

    constexpr size_t GCM_IV_LENGTH = 12;
    constexpr size_t GCM_TAG_LENGTH = 16;

    std::optional<std::vector<uint8_t>> AesGcm::Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& encryptedData) {
        // EXACTLY like the working payload's DecryptGcm function
        if (encryptedData.size() < 3 + GCM_IV_LENGTH + GCM_TAG_LENGTH)
            return std::nullopt;

        // Determine prefix length (v10/v11/v20) - EXACT MATCH TO WORKING PAYLOAD
        size_t prefix_len = 0;
        if (memcmp(encryptedData.data(), "v20", 3) == 0 || 
            memcmp(encryptedData.data(), "v10", 3) == 0 || 
            memcmp(encryptedData.data(), "v11", 3) == 0) {
            prefix_len = 3;
        } else {
            return std::nullopt; // No valid prefix found
        }

        const uint8_t* iv = encryptedData.data() + prefix_len;
        const uint8_t* ct = iv + GCM_IV_LENGTH;
        const uint8_t* tag = encryptedData.data() + (encryptedData.size() - GCM_TAG_LENGTH);
        ULONG ct_len = static_cast<ULONG>(encryptedData.size() - prefix_len - GCM_IV_LENGTH - GCM_TAG_LENGTH);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            return std::nullopt;
        
        auto algCloser = [](BCRYPT_ALG_HANDLE h) { 
            if (h) BCryptCloseAlgorithmProvider(h, 0); 
        };
        std::unique_ptr<void, decltype(algCloser)> algGuard(hAlg, algCloser);

        if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
            return std::nullopt;

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                   (PUCHAR)key.data(),
                                                   (ULONG)key.size(), 0)))
            return std::nullopt;
        
        auto keyCloser = [](BCRYPT_KEY_HANDLE h) { 
            if (h) BCryptDestroyKey(h); 
        };
        std::unique_ptr<void, decltype(keyCloser)> keyGuard(hKey, keyCloser);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv;
        authInfo.cbNonce = GCM_IV_LENGTH;
        authInfo.pbTag = (PUCHAR)tag;
        authInfo.cbTag = GCM_TAG_LENGTH;

        std::vector<uint8_t> plain(ct_len > 0 ? ct_len : 1);
        ULONG outLen = 0;
        
        NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &authInfo,
                                        nullptr, 0, plain.data(),
                                        (ULONG)plain.size(), &outLen, 0);
        
        if (!NT_SUCCESS(status)) {
            return std::nullopt;
        }

        plain.resize(outLen);
        return plain;
    }

}