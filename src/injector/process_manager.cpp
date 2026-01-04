// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "process_manager.hpp"
#include "../sys/internal_api.hpp"
#include <iostream>

namespace Injector {

    ProcessManager::ProcessManager(const BrowserInfo& browser) : m_browser(browser) {}

    ProcessManager::~ProcessManager() {
        // Ensure cleanup if not explicitly terminated
        if (m_hProcess) Terminate();
    }

    void ProcessManager::CreateSuspended() {
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (!CreateProcessW(m_browser.fullPath.c_str(), nullptr, nullptr, nullptr,
                            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            throw std::runtime_error("CreateProcessW failed: " + std::to_string(GetLastError()));
        }

        m_hProcess.reset(pi.hProcess);
        m_hThread.reset(pi.hThread);
        m_pid = pi.dwProcessId;

        CheckArchitecture();
    }

    void ProcessManager::Terminate() {
        if (m_hProcess) {
            NtTerminateProcess_syscall(m_hProcess.get(), 0);
            WaitForSingleObject(m_hProcess.get(), 2000);
            m_hProcess.reset(); // Release handle
        }
    }

    void ProcessManager::CheckArchitecture() {
        USHORT processArch = 0, nativeMachine = 0;
        auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        
        if (!fnIsWow64Process2 || !fnIsWow64Process2(m_hProcess.get(), &processArch, &nativeMachine)) {
            throw std::runtime_error("Failed to determine target architecture");
        }

        m_arch = (processArch == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processArch;

        // Architecture names for human-readable errors
        auto GetArchName = [](USHORT arch) -> std::string {
            switch (arch) {
                case 0x8664: return "x64 (AMD64)";
                case 0xAA64: return "ARM64";
                case 0x014C: return "x86 (i386)";
                case 0x01C4: return "ARM (Thumb-2)";
                default: return "Unknown (0x" + std::to_string(arch) + ")";
            }
        };

        // Injector is x64 or ARM64 (native)
#if defined(_M_X64)
        constexpr USHORT injectorArch = 0x8664; // AMD64
        constexpr const char* injectorArchName = "x64";
#elif defined(_M_ARM64)
        constexpr USHORT injectorArch = 0xAA64; // ARM64
        constexpr const char* injectorArchName = "ARM64";
#else
        constexpr USHORT injectorArch = 0;
        constexpr const char* injectorArchName = "Unknown";
#endif

        if (m_arch != injectorArch) {
            std::string error = "Architecture mismatch!\n";
            error += "  Injector: " + std::string(injectorArchName) + "\n";
            error += "  Target:   " + GetArchName(m_arch) + "\n";
            error += "  Solution: Use chromelevator_" + std::string(m_arch == 0xAA64 ? "arm64" : "x64") + ".exe";
            throw std::runtime_error(error);
        }
    }

}
