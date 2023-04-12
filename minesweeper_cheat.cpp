#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

DWORD GetProcID(const wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_wcsicmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t moduleBaseAddress = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnap, &moduleEntry))
        {
            do
            {
                if (!_wcsicmp(moduleEntry.szModule, modName))
                {
                    moduleBaseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &moduleEntry));
        }
    }
    CloseHandle(hSnap);

    return moduleBaseAddress;
}

uintptr_t getAddress(std::vector<unsigned int> offsets, uintptr_t ptr, HANDLE hProc)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); i++)
    {
        ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}

void PatchEx(BYTE* dest, BYTE* src, unsigned int size, HANDLE hProc)
{
    DWORD oldprotect;
    VirtualProtectEx(hProc, dest, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    WriteProcessMemory(hProc, dest, src, size, nullptr);
    VirtualProtectEx(hProc, dest, size, oldprotect, &oldprotect);
}

int main()
{
    const wchar_t gameName[] = L"WINMINE.EXE";

    //HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    HANDLE hProc = 0;

    uintptr_t modBaseAddr = 0, timeAddr = 0;

    DWORD procId = GetProcID(gameName);

    
    if (procId)
    {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
        uintptr_t modBaseAddr = GetModuleBaseAddress(procId, gameName);
        uintptr_t timeAddr = getAddress({ 0x2FE0 }, modBaseAddr, hProc);

        PatchEx((BYTE*)0x01002FE0, (BYTE*)"\xC2", 7, hProc);
        //WriteProcessMemory(hProc, (BYTE*)timeAddr, (BYTE*)"\xC2", 7, nullptr);

        std::cout << "Minesweeper patched" << std::endl;
        std::cout << modBaseAddr;

    }
    else
    {
        std::cout << "could not find process";
        return 0;
    }
    CloseHandle(hProc);
    return 0;
}
