// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <vector>
#include <iomanip>

namespace Payload {

    class FingerprintExtractor {
    public:
        FingerprintExtractor(PipeClient& pipe, const BrowserConfig& browser, 
                             const std::filesystem::path& outputBase)
            : m_pipe(pipe), m_browser(browser), m_outputBase(outputBase) {}

        void Extract() {
            m_pipe.Log("FINGERPRINT_START:" + m_browser.name);
            
            // Send summary count (will show as "Fingerprint: 1" in console)
            m_pipe.Log("FINGERPRINT:1");
            
            // Extract and send all fingerprint data
            ExtractAndSendVersion();
            ExtractAndSendLocalState();
            ExtractAndSendPreferences();
            ExtractAndSendExtensions();
            ExtractAndSendSystemInfo();
            ExtractAndSendTimestamps();
            
            m_pipe.LogDebug("Fingerprint extraction complete");
        }

    private:
        void ExtractAndSendVersion() {
            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            
            m_pipe.Log("FINGERPRINT_DATA:executable_path|" + std::string(exePath));
            m_pipe.Log("FINGERPRINT_DATA:user_data_path|" + m_browser.userDataPath.string());
            
            DWORD handle = 0;
            DWORD versionSize = GetFileVersionInfoSizeA(exePath, &handle);
            if (versionSize > 0) {
                std::vector<BYTE> versionData(versionSize);
                if (GetFileVersionInfoA(exePath, 0, versionSize, versionData.data())) {
                    VS_FIXEDFILEINFO* fileInfo = nullptr;
                    UINT len = 0;
                    if (VerQueryValueA(versionData.data(), "\\", (LPVOID*)&fileInfo, &len) && len > 0) {
                        std::string version = std::to_string(HIWORD(fileInfo->dwFileVersionMS)) + "." +
                                            std::to_string(LOWORD(fileInfo->dwFileVersionMS)) + "." +
                                            std::to_string(HIWORD(fileInfo->dwFileVersionLS)) + "." +
                                            std::to_string(LOWORD(fileInfo->dwFileVersionLS));
                        m_pipe.Log("FINGERPRINT_DATA:browser_version|" + version);
                    }
                }
            }
        }

        void ExtractAndSendLocalState() {
            auto localStatePath = m_browser.userDataPath / "Local State";
            if (!std::filesystem::exists(localStatePath)) return;

            std::ifstream f(localStatePath);
            if (!f) return;

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            
            // Sync/account status
            m_pipe.Log("FINGERPRINT_DATA:sync_enabled|" + std::string(ContainsKey(content, "account_info") ? "Yes" : "No"));
            
            // Enterprise management
            m_pipe.Log("FINGERPRINT_DATA:enterprise_managed|" + std::string(ContainsKey(content, "enterprise") ? "Yes" : "No"));
            
            // Update channel detection
            std::string channel = "stable";
            if (ContainsKey(content, "\"canary\"")) channel = "canary";
            else if (ContainsKey(content, "\"dev\"")) channel = "dev";
            else if (ContainsKey(content, "\"beta\"")) channel = "beta";
            m_pipe.Log("FINGERPRINT_DATA:update_channel|" + channel);
            
            // Default search engine
            size_t searchPos = content.find("default_search_provider_data");
            if (searchPos != std::string::npos) {
                std::string searchEngine = "unknown";
                std::string searchSection = content.substr(searchPos, std::min<size_t>(2000, content.size() - searchPos));
                if (searchSection.find("google") != std::string::npos) searchEngine = "Google";
                else if (searchSection.find("bing") != std::string::npos) searchEngine = "Bing";
                else if (searchSection.find("duckduckgo") != std::string::npos) searchEngine = "DuckDuckGo";
                else if (searchSection.find("yahoo") != std::string::npos) searchEngine = "Yahoo";
                else if (searchSection.find("ecosia") != std::string::npos) searchEngine = "Ecosia";
                m_pipe.Log("FINGERPRINT_DATA:default_search_engine|" + searchEngine);
            }
            
            // Hardware acceleration
            m_pipe.Log("FINGERPRINT_DATA:hardware_acceleration|" + std::string(ContainsKey(content, "hardware_acceleration_mode_enabled") ? "Yes" : "No"));
            
            // Browser metrics consent
            m_pipe.Log("FINGERPRINT_DATA:metrics_enabled|" + std::string(ContainsKey(content, "\"enabled\":true", "metrics") ? "Yes" : "No"));
        }

        void ExtractAndSendPreferences() {
            auto prefsPath = m_browser.userDataPath / "Default" / "Preferences";
            if (!std::filesystem::exists(prefsPath)) return;

            std::ifstream f(prefsPath);
            if (!f) return;

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            
            // Security features
            m_pipe.Log("FINGERPRINT_DATA:autofill_enabled|" + std::string(ContainsKey(content, "autofill") ? "Yes" : "No"));
            m_pipe.Log("FINGERPRINT_DATA:password_manager_enabled|" + std::string(ContainsKey(content, "credentials_enable_service") ? "Yes" : "No"));
            m_pipe.Log("FINGERPRINT_DATA:safe_browsing_enabled|" + std::string(ContainsKey(content, "safebrowsing") ? "Yes" : "No"));
            
            // Additional security settings
            m_pipe.Log("FINGERPRINT_DATA:do_not_track|" + std::string(ContainsKey(content, "enable_do_not_track") ? "Yes" : "No"));
            m_pipe.Log("FINGERPRINT_DATA:third_party_cookies_blocked|" + std::string(ContainsKey(content, "block_third_party_cookies") ? "Yes" : "No"));
            
            // Privacy settings
            m_pipe.Log("FINGERPRINT_DATA:translate_enabled|" + std::string(ContainsKey(content, "translate") && !ContainsKey(content, "\"translate\":{\"enabled\":false}") ? "Yes" : "No"));
        }

        void ExtractAndSendExtensions() {
            auto extensionsPath = m_browser.userDataPath / "Default" / "Extensions";
            int extensionCount = 0;
            
            if (std::filesystem::exists(extensionsPath)) {
                try {
                    for (const auto& entry : std::filesystem::directory_iterator(extensionsPath)) {
                        if (entry.is_directory()) {
                            extensionCount++;
                        }
                    }
                } catch (...) {}
            }
            
            m_pipe.Log("FINGERPRINT_DATA:installed_extensions_count|" + std::to_string(extensionCount));
        }

        void ExtractAndSendSystemInfo() {
            // Computer name
            char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
            DWORD size = sizeof(computerName);
            if (GetComputerNameA(computerName, &size)) {
                m_pipe.Log("FINGERPRINT_DATA:computer_name|" + std::string(computerName));
            }

            // Windows username
            char userName[256] = {0};
            DWORD userSize = sizeof(userName);
            if (GetUserNameA(userName, &userSize)) {
                m_pipe.Log("FINGERPRINT_DATA:windows_user|" + std::string(userName));
            }

            // OS Version info
            OSVERSIONINFOEXW osInfo = {0};
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            
            using RtlGetVersionPtr = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
            if (auto ntdll = GetModuleHandleW(L"ntdll.dll")) {
                if (auto pRtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(GetProcAddress(ntdll, "RtlGetVersion"))) {
                    if (pRtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osInfo)) == 0) {
                        std::string osVersion = std::to_string(osInfo.dwMajorVersion) + "." + 
                                               std::to_string(osInfo.dwMinorVersion) + "." + 
                                               std::to_string(osInfo.dwBuildNumber);
                        m_pipe.Log("FINGERPRINT_DATA:os_version|" + osVersion);
                    }
                }
            }

            // Architecture
            SYSTEM_INFO sysInfo;
            GetNativeSystemInfo(&sysInfo);
            std::string arch = "unknown";
            switch (sysInfo.wProcessorArchitecture) {
                case PROCESSOR_ARCHITECTURE_AMD64: arch = "x64"; break;
                case PROCESSOR_ARCHITECTURE_ARM64: arch = "ARM64"; break;
                case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
            }
            m_pipe.Log("FINGERPRINT_DATA:architecture|" + arch);
        }

        void ExtractAndSendTimestamps() {
            // Current extraction time
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            m_pipe.Log("FINGERPRINT_DATA:extraction_timestamp|" + std::to_string(now));
        }

        bool ContainsKey(const std::string& content, const std::string& key, const std::string& context = "") {
            if (context.empty()) {
                return content.find(key) != std::string::npos;
            }
            size_t contextPos = content.find(context);
            if (contextPos == std::string::npos) return false;
            size_t keyPos = content.find(key, contextPos);
            return keyPos != std::string::npos && keyPos < contextPos + 500;
        }

        PipeClient& m_pipe;
        const BrowserConfig& m_browser;
        std::filesystem::path m_outputBase;
    };

}