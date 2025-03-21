#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <filesystem>
#include <unordered_set>

namespace fs = std::filesystem;

bool Is32BitProcess(DWORD processId)
{
    BOOL isWow64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess)
    {
        IsWow64Process(hProcess, &isWow64);
        CloseHandle(hProcess);
    }
    return isWow64;
}

bool InjectDll(DWORD processId, const std::wstring& dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        std::wcerr << L"Failed to open process " << processId << L". Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, nullptr, (dllPath.size() + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory)
    {
        std::wcerr << L"Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }


    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), (dllPath.size() + 1) * sizeof(wchar_t), nullptr))
    {
        std::wcerr << L"Failed to write to target process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary)
    {
        std::wcerr << L"Failed to get address of LoadLibraryW. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, nullptr);
    if (!hRemoteThread)
    {
        std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    DWORD waitResult = WaitForSingleObject(hRemoteThread, 5000); // Wait for 5 seconds
    if (waitResult == WAIT_TIMEOUT)
    {
        std::wcerr << L"Remote thread timed out. Terminating thread." << std::endl;
        TerminateThread(hRemoteThread, 0);
    }

    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return true;
}

int main()
{
    std::wstring dllPath32 = L"32 bit DLL FILE path";
    std::wstring dllPath64 = L"64 bit DLL FILE path";

    std::unordered_set<DWORD> injectedProcesses; // Track injected processes
    std::unordered_set<DWORD> blacklistedProcesses; // Track blacklisted processes

    std::wcout << L"Starting DLL injection monitor. Press 'Q' to quit." << std::endl;

    while (true)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::wcerr << L"Failed to create process snapshot. Error: " << GetLastError() << std::endl;
            Sleep(5000); // Wait before retrying
            continue;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe))
        {
            std::wcerr << L"Failed to enumerate processes. Error: " << GetLastError() << std::endl;
            CloseHandle(hSnapshot);
            Sleep(5000); // Wait before retrying
            continue;
        }

        do
        {
            if (_wcsicmp(pe.szExeFile, L"Loader.exe") == 0)
                continue;

            // Skip if the process is blacklisted
            if (blacklistedProcesses.find(pe.th32ProcessID) != blacklistedProcesses.end())
            {
                continue; // Skip without logging
            }

            // Skip if the process has already been injected
            if (injectedProcesses.find(pe.th32ProcessID) != injectedProcesses.end())
                continue;

            if (Is32BitProcess(pe.th32ProcessID))
            {
                if (!fs::exists(dllPath32))
                {
                    std::wcerr << L"32-bit DLL not found at: " << dllPath32 << std::endl;
                    continue;
                }
                std::wcout << L"Injecting 32-bit DLL into process: " << pe.szExeFile << std::endl;
                if (InjectDll(pe.th32ProcessID, dllPath32))
                {
                    injectedProcesses.insert(pe.th32ProcessID); // Mark as injected
                }
                else
                {
                    blacklistedProcesses.insert(pe.th32ProcessID); // Add to blacklist
                    std::wcerr << L"Failed to inject into process: " << pe.szExeFile << L". Added to blacklist." << std::endl;
                }
            }
            else
            {
                if (!fs::exists(dllPath64))
                {
                    std::wcerr << L"64-bit DLL not found at: " << dllPath64 << std::endl;
                    continue;
                }
                std::wcout << L"Injecting 64-bit DLL into process: " << pe.szExeFile << std::endl;
                if (InjectDll(pe.th32ProcessID, dllPath64))
                {
                    injectedProcesses.insert(pe.th32ProcessID); // Mark as injected
                }
                else
                {
                    blacklistedProcesses.insert(pe.th32ProcessID); // Add to blacklist
                    std::wcerr << L"Failed to inject into process: " << pe.szExeFile << L". Added to blacklist." << std::endl;
                }
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);

        // Check for user input to quit
        if (GetAsyncKeyState('Q') & 0x8000) // Check if 'Q' is pressed
        {
            std::wcout << L"Exiting..." << std::endl;
            break;
        }

        Sleep(1000); // Wait for 1 second before checking again
    }

    return 0;
}