#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

#define STELLA_CFG_NAME "stella.cfg"
#define STELLA_LOG_NAME "stella_debug.log"
#define MORRENUS_HOST   L"manifest.morrenus.xyz"
#define MAX_URL_LEN     512
#define MAX_RESPONSE    8192
#define MAX_KEY_LEN     128
#define CONNECT_TIMEOUT 10000
#define REQUEST_TIMEOUT 15000

static char g_api_key[MAX_KEY_LEN];
static int  g_key_loaded = 0;
static char g_log_path[MAX_PATH];
static int  g_log_init = 0;

static void init_log_path(void)
{
    if (g_log_init) return;
    g_log_init = 1;
    g_log_path[0] = '\0';

    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;

    char *sep = strrchr(path, '\\');
    if (!sep) return;
    *(sep + 1) = '\0';

    if (strlen(path) + strlen(STELLA_LOG_NAME) >= MAX_PATH) return;
    strcpy(g_log_path, path);
    strcat(g_log_path, STELLA_LOG_NAME);
}

static void dbglog(const char *fmt, ...)
{
    init_log_path();
    if (g_log_path[0] == '\0') return;

    FILE *f = fopen(g_log_path, "a");
    if (!f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fprintf(f, "\n");
    fclose(f);
}

static int load_api_key(void)
{
    if (g_key_loaded)
        return g_api_key[0] != '\0';

    g_key_loaded = 1;
    g_api_key[0] = '\0';

    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return 0;

    char *last_sep = strrchr(path, '\\');
    if (!last_sep)
        return 0;

    *(last_sep + 1) = '\0';
    if (strlen(path) + strlen(STELLA_CFG_NAME) >= MAX_PATH)
        return 0;

    strcat(path, STELLA_CFG_NAME);
    dbglog("load_api_key: trying path: %s", path);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        dbglog("load_api_key: CreateFileA failed, err=%lu", GetLastError());
        return 0;
    }

    DWORD bytes_read = 0;
    char buf[MAX_KEY_LEN + 16];
    BOOL ok = ReadFile(hFile, buf, sizeof(buf) - 1, &bytes_read, NULL);
    CloseHandle(hFile);

    if (!ok || bytes_read == 0)
    {
        dbglog("load_api_key: ReadFile failed or empty, ok=%d bytes=%lu", ok, bytes_read);
        return 0;
    }

    buf[bytes_read] = '\0';

    char *start = buf;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
        start++;

    char *end = start + strlen(start);
    while (end > start && (*(end-1) == ' ' || *(end-1) == '\t' ||
                           *(end-1) == '\r' || *(end-1) == '\n'))
        end--;
    *end = '\0';

    if (strlen(start) == 0 || strlen(start) >= MAX_KEY_LEN)
    {
        dbglog("load_api_key: key invalid length (%zu)", strlen(start));
        return 0;
    }

    strcpy(g_api_key, start);
    dbglog("load_api_key: loaded key (len=%zu)", strlen(g_api_key));
    return 1;
}

static unsigned __int64 parse_request_code(const char *json, DWORD json_len)
{
    const char *needle = "\"request_code\"";
    size_t needle_len = strlen(needle);

    const char *pos = json;
    const char *end = json + json_len;

    while (pos + needle_len < end) {
        pos = memchr(pos, '"', end - pos);
        if (!pos)
            return 0;

        if ((size_t)(end - pos) >= needle_len &&
            memcmp(pos, needle, needle_len) == 0) {
            pos += needle_len;
            break;
        }
        pos++;
    }

    if (pos >= end)
        return 0;

    while (pos < end && (*pos == ' ' || *pos == ':' || *pos == '\t'))
        pos++;

    if (pos < end && *pos == '"')
        pos++;

    char num_buf[32];
    int i = 0;
    while (pos < end && i < 30) {
        char c = *pos;
        if (c >= '0' && c <= '9') {
            num_buf[i++] = c;
            pos++;
        } else {
            break;
        }
    }
    num_buf[i] = '\0';

    if (i == 0)
        return 0;

    return _strtoui64(num_buf, NULL, 10);
}

__declspec(dllexport) unsigned __int64 __fastcall StellaGetRequestCode(
    unsigned __int64 depot_id,
    unsigned __int64 manifest_id)
{
    dbglog("StellaGetRequestCode: depot=%llu manifest=%llu",
           depot_id, manifest_id);

    if (!load_api_key())
    {
        dbglog("no API key");
        return 0;
    }

    char path_a[MAX_URL_LEN];
    _snprintf(path_a, MAX_URL_LEN,
              "/api/v1/generate/requestcode?depot_id=%llu&manifest_id=%llu",
              depot_id, manifest_id);
    path_a[MAX_URL_LEN - 1] = '\0';

    WCHAR path_w[MAX_URL_LEN];
    MultiByteToWideChar(CP_UTF8, 0, path_a, -1, path_w, MAX_URL_LEN);

    /* build Authorization: Bearer header */
    char auth_a[MAX_KEY_LEN + 32];
    _snprintf(auth_a, sizeof(auth_a), "Authorization: Bearer %s", g_api_key);
    auth_a[sizeof(auth_a) - 1] = '\0';

    WCHAR auth_w[MAX_KEY_LEN + 32];
    MultiByteToWideChar(CP_UTF8, 0, auth_a, -1, auth_w, MAX_KEY_LEN + 32);

    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    unsigned __int64 result = 0;

    hSession = WinHttpOpen(L"Stella/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        dbglog("http init failed (%lu)", GetLastError());
        goto cleanup;
    }

    WinHttpSetTimeouts(hSession, CONNECT_TIMEOUT, CONNECT_TIMEOUT,
                       REQUEST_TIMEOUT, REQUEST_TIMEOUT);

    hConnect = WinHttpConnect(hSession, MORRENUS_HOST,
                              INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
        goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", path_w,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest)
        goto cleanup;

    if (!WinHttpSendRequest(hRequest, auth_w, (DWORD)-1L,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        dbglog("request failed (%lu)", GetLastError());
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL))
    {
        dbglog("no response (%lu)", GetLastError());
        goto cleanup;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);

    dbglog("HTTP %lu", status_code);

    if (status_code != 200)
    {
        /* read body for error details */
        char errbuf[1024];
        DWORD errread = 0, avail = 0;
        if (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            if (avail > sizeof(errbuf) - 1) avail = sizeof(errbuf) - 1;
            WinHttpReadData(hRequest, errbuf, avail, &errread);
            errbuf[errread] = '\0';
            dbglog("error: %s", errbuf);
        }
        goto cleanup;
    }

    char response[MAX_RESPONSE];
    DWORD total_read = 0;
    DWORD available = 0;

    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        if (total_read + available > MAX_RESPONSE - 1)
            available = MAX_RESPONSE - 1 - total_read;
        if (available == 0)
            break;

        DWORD bytes_read = 0;
        if (!WinHttpReadData(hRequest, response + total_read, available, &bytes_read))
            break;
        total_read += bytes_read;
    }

    if (total_read == 0)
    {
        dbglog("empty response");
        goto cleanup;
    }

    response[total_read] = '\0';
    dbglog("response: %.*s", (int)total_read, response);

    result = parse_request_code(response, total_read);
    dbglog("request_code=%llu", result);

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        dbglog("stella_fallback loaded");
    }
    return TRUE;
}
