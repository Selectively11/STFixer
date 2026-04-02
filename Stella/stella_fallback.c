#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

#define STELLA_CFG_NAME      "stella.cfg"
#define STELLA_LOG_NAME      "stella_debug.log"
#define STELLA_LOCKOUT_NAME  "stella_ratelimit.dat"
#define MORRENUS_HOST        L"manifest.morrenus.xyz"
#define MAX_URL_LEN          512
#define MAX_RESPONSE         8192
#define MAX_KEY_LEN          128
#define CONNECT_TIMEOUT      10000
#define REQUEST_TIMEOUT      15000

// rate limit / backoff
#define BACKOFF_INITIAL_MS   1000
#define BACKOFF_MAX_MS       60000
#define BACKOFF_DECAY_MS     120000

// stats re-check interval when limited
#define STATS_RECHECK_MS     3600000 // 1 hour

// request code cache
#define CACHE_MAX_ENTRIES    1024
#define CACHE_TTL_MS         240000  // 4 minutes

typedef struct {
    unsigned __int64 depot_id;
    unsigned __int64 manifest_id;
    unsigned __int64 request_code;
    ULONGLONG tick;
} CacheEntry;

static char g_api_key[MAX_KEY_LEN];
static int  g_key_loaded = 0;
static char g_log_path[MAX_PATH];
static int  g_log_init = 0;
static char g_exe_dir[MAX_PATH];
static int  g_auth_warned = 0;
static int  g_daily_warned = 0;

// rate limiting state
static int  g_daily_limit_hit = 0;
static DWORD g_backoff_ms = 0;
static ULONGLONG g_last_429_tick = 0;

// stats check state
static int  g_stats_checked = 0;
static ULONGLONG g_last_stats_tick = 0;

// request code cache
static CacheEntry g_cache[CACHE_MAX_ENTRIES];
static int g_cache_count = 0;
static CRITICAL_SECTION g_cache_cs;
static int g_cs_init = 0;

// ---- utility helpers ----

static void ensure_cs(void)
{
    if (!g_cs_init) {
        InitializeCriticalSection(&g_cache_cs);
        g_cs_init = 1;
    }
}

static int get_exe_dir(void)
{
    if (g_exe_dir[0] != '\0') return 1;
    DWORD len = GetModuleFileNameA(NULL, g_exe_dir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) { g_exe_dir[0] = '\0'; return 0; }
    char *sep = strrchr(g_exe_dir, '\\');
    if (!sep) { g_exe_dir[0] = '\0'; return 0; }
    *(sep + 1) = '\0';
    return 1;
}

static void init_log_path(void)
{
    if (g_log_init) return;
    g_log_init = 1;
    g_log_path[0] = '\0';
    if (!get_exe_dir()) return;
    if (strlen(g_exe_dir) + strlen(STELLA_LOG_NAME) >= MAX_PATH) return;
    strcpy(g_log_path, g_exe_dir);
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

// ---- lockout file (cross-process hint) ----

static void write_lockout(void)
{
    if (!get_exe_dir()) return;
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "%s%s", g_exe_dir, STELLA_LOCKOUT_NAME);
    path[MAX_PATH - 1] = '\0';
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    // just a marker — content doesn't matter
    CloseHandle(hf);
}

static void delete_lockout(void)
{
    if (!get_exe_dir()) return;
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "%s%s", g_exe_dir, STELLA_LOCKOUT_NAME);
    path[MAX_PATH - 1] = '\0';
    DeleteFileA(path);
}

static int lockout_exists(void)
{
    if (!get_exe_dir()) return 0;
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "%s%s", g_exe_dir, STELLA_LOCKOUT_NAME);
    path[MAX_PATH - 1] = '\0';
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

// ---- JSON parsing helpers ----

// find "key" in json, return pointer to the value (after colon + whitespace)
static const char *json_find_value(const char *json, const char *key)
{
    char needle[128];
    _snprintf(needle, sizeof(needle), "\"%s\"", key);
    needle[sizeof(needle) - 1] = '\0';

    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    return p;
}

// parse an integer value for a given JSON key. returns -1 if not found.
static int json_get_int(const char *json, const char *key)
{
    const char *v = json_find_value(json, key);
    if (!v) return -1;
    if (*v < '0' || *v > '9') return -1;
    return atoi(v);
}

// parse a boolean value for a given JSON key. returns -1 if not found.
static int json_get_bool(const char *json, const char *key)
{
    const char *v = json_find_value(json, key);
    if (!v) return -1;
    if (strncmp(v, "true", 4) == 0) return 1;
    if (strncmp(v, "false", 5) == 0) return 0;
    return -1;
}

// ---- API key loading ----

static int load_api_key(void)
{
    if (g_key_loaded)
        return g_api_key[0] != '\0';

    g_key_loaded = 1;
    g_api_key[0] = '\0';

    if (!get_exe_dir()) return 0;

    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "%s%s", g_exe_dir, STELLA_CFG_NAME);
    path[MAX_PATH - 1] = '\0';

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

// ---- HTTP helper ----

// make a GET request to MORRENUS_HOST. returns HTTP status code, or 0 on error.
// response body written to out_buf (null-terminated), out_len set to body length.
static DWORD http_get(const WCHAR *path_w, const WCHAR *extra_headers,
                      char *out_buf, DWORD out_max, DWORD *out_len)
{
    *out_len = 0;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD status_code = 0;

    hSession = WinHttpOpen(L"Stella/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto done;

    WinHttpSetTimeouts(hSession, CONNECT_TIMEOUT, CONNECT_TIMEOUT,
                       REQUEST_TIMEOUT, REQUEST_TIMEOUT);

    hConnect = WinHttpConnect(hSession, MORRENUS_HOST,
                              INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) goto done;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", path_w,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) goto done;

    LPCWSTR hdrs = extra_headers ? extra_headers : WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD hdrs_len = extra_headers ? (DWORD)-1L : 0;

    if (!WinHttpSendRequest(hRequest, hdrs, hdrs_len,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto done;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto done;

    DWORD sc_size = sizeof(status_code);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status_code, &sc_size, WINHTTP_NO_HEADER_INDEX);

    // read body
    DWORD total = 0, avail = 0;
    while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        if (total + avail > out_max - 1)
            avail = out_max - 1 - total;
        if (avail == 0) break;
        DWORD rd = 0;
        if (!WinHttpReadData(hRequest, out_buf + total, avail, &rd)) break;
        total += rd;
    }
    out_buf[total] = '\0';
    *out_len = total;

done:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return status_code;
}

// ---- daily limit notification ----

static void notify_daily_limit(void)
{
    if (g_daily_warned) return;
    g_daily_warned = 1;
    MessageBoxA(NULL,
        "You hit your daily manifest request limit :(\n\n"
        "Manifest downloads will resume when your limit resets.",
        "STFixer", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
}

// ---- stats check ----

// query the stats endpoint. returns: 1 = can make requests, 0 = limited, -1 = error.
static int query_stats(void)
{
    char path_a[MAX_URL_LEN];
    _snprintf(path_a, MAX_URL_LEN,
              "/api/v1/user/stats?api_key=%s", g_api_key);
    path_a[MAX_URL_LEN - 1] = '\0';

    WCHAR path_w[MAX_URL_LEN];
    MultiByteToWideChar(CP_UTF8, 0, path_a, -1, path_w, MAX_URL_LEN);

    char body[MAX_RESPONSE];
    DWORD body_len = 0;
    DWORD status = http_get(path_w, NULL, body, MAX_RESPONSE, &body_len);

    if (status != 200) {
        dbglog("stats check: HTTP %lu", status);
        return -1;
    }

    int can_make = json_get_bool(body, "can_make_requests");
    int usage = json_get_int(body, "daily_usage");
    int limit = json_get_int(body, "daily_limit");

    dbglog("stats: can_make_requests=%d, daily_usage=%d/%d",
           can_make, usage, limit);

    if (can_make == 0) return 0;  // server says no
    if (can_make == 1) return 1;  // server says yes

    // fallback: parse usage/limit if can_make_requests field missing
    if (usage >= 0 && limit > 0)
        return (usage < limit) ? 1 : 0;

    return -1;  // couldn't determine
}

// check stats and update daily limit state. called on first request and periodically.
static void do_stats_check(void)
{
    g_last_stats_tick = GetTickCount64();

    int result = query_stats();
    if (result == 1) {
        // we're good — clear any limit
        if (g_daily_limit_hit) {
            dbglog("daily limit cleared by stats check");
            g_daily_limit_hit = 0;
            delete_lockout();
        }
    } else if (result == 0) {
        // limited
        if (!g_daily_limit_hit) {
            dbglog("daily limit confirmed by stats check");
            g_daily_limit_hit = 1;
            write_lockout();
            notify_daily_limit();
        }
    }
    // result == -1: couldn't reach stats, don't change state
}

// ---- request code cache ----

static unsigned __int64 cache_get(unsigned __int64 depot_id,
                                   unsigned __int64 manifest_id)
{
    ULONGLONG now = GetTickCount64();
    EnterCriticalSection(&g_cache_cs);
    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].depot_id == depot_id &&
            g_cache[i].manifest_id == manifest_id) {
            if (now - g_cache[i].tick < CACHE_TTL_MS) {
                unsigned __int64 rc = g_cache[i].request_code;
                LeaveCriticalSection(&g_cache_cs);
                return rc;
            }
            g_cache[i] = g_cache[--g_cache_count];
            LeaveCriticalSection(&g_cache_cs);
            return 0;
        }
    }
    LeaveCriticalSection(&g_cache_cs);
    return 0;
}

static void cache_put(unsigned __int64 depot_id,
                      unsigned __int64 manifest_id,
                      unsigned __int64 request_code)
{
    ULONGLONG now = GetTickCount64();
    EnterCriticalSection(&g_cache_cs);

    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].depot_id == depot_id &&
            g_cache[i].manifest_id == manifest_id) {
            g_cache[i].request_code = request_code;
            g_cache[i].tick = now;
            LeaveCriticalSection(&g_cache_cs);
            return;
        }
    }

    int slot = g_cache_count;
    if (slot >= CACHE_MAX_ENTRIES) {
        ULONGLONG oldest = g_cache[0].tick;
        slot = 0;
        for (int i = 1; i < CACHE_MAX_ENTRIES; i++) {
            if (g_cache[i].tick < oldest) {
                oldest = g_cache[i].tick;
                slot = i;
            }
        }
    } else {
        g_cache_count++;
    }

    g_cache[slot].depot_id = depot_id;
    g_cache[slot].manifest_id = manifest_id;
    g_cache[slot].request_code = request_code;
    g_cache[slot].tick = now;
    LeaveCriticalSection(&g_cache_cs);
}

// ---- request code JSON parser ----

static unsigned __int64 parse_request_code(const char *json, DWORD json_len)
{
    const char *needle = "\"request_code\"";
    size_t needle_len = strlen(needle);

    const char *pos = json;
    const char *end = json + json_len;

    while (pos + needle_len < end) {
        pos = memchr(pos, '"', end - pos);
        if (!pos) return 0;
        if ((size_t)(end - pos) >= needle_len &&
            memcmp(pos, needle, needle_len) == 0) {
            pos += needle_len;
            break;
        }
        pos++;
    }

    if (pos >= end) return 0;

    while (pos < end && (*pos == ' ' || *pos == ':' || *pos == '\t'))
        pos++;
    if (pos < end && *pos == '"')
        pos++;

    char num_buf[32];
    int i = 0;
    while (pos < end && i < 30) {
        char c = *pos;
        if (c >= '0' && c <= '9') { num_buf[i++] = c; pos++; }
        else break;
    }
    num_buf[i] = '\0';

    if (i == 0) return 0;
    return _strtoui64(num_buf, NULL, 10);
}

// ---- main export ----

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

    // first call: check stats to see if we can make requests
    if (!g_stats_checked)
    {
        g_stats_checked = 1;
        dbglog("initial stats check");
        do_stats_check();
    }

    // if daily-limited, periodically re-check stats in case limit resets
    if (g_daily_limit_hit)
    {
        ULONGLONG now = GetTickCount64();
        if (now - g_last_stats_tick >= STATS_RECHECK_MS)
        {
            dbglog("re-checking stats (daily limit active)");
            do_stats_check();
        }
        if (g_daily_limit_hit)
            return 0;
    }

    // check cache
    unsigned __int64 cached = cache_get(depot_id, manifest_id);
    if (cached != 0)
    {
        dbglog("cache hit, request_code=%llu", cached);
        return cached;
    }

    // backoff from per-minute rate limit
    if (g_backoff_ms > 0)
    {
        ULONGLONG now = GetTickCount64();
        if (now - g_last_429_tick >= BACKOFF_DECAY_MS) {
            g_backoff_ms = 0;
        } else {
            dbglog("backoff: sleeping %lu ms", g_backoff_ms);
            Sleep(g_backoff_ms);
        }
    }

    // build request URL
    char path_a[MAX_URL_LEN];
    _snprintf(path_a, MAX_URL_LEN,
              "/api/v1/generate/requestcode?depot_id=%llu&manifest_id=%llu",
              depot_id, manifest_id);
    path_a[MAX_URL_LEN - 1] = '\0';

    WCHAR path_w[MAX_URL_LEN];
    MultiByteToWideChar(CP_UTF8, 0, path_a, -1, path_w, MAX_URL_LEN);

    // build auth header
    char auth_a[MAX_KEY_LEN + 32];
    _snprintf(auth_a, sizeof(auth_a), "Authorization: Bearer %s", g_api_key);
    auth_a[sizeof(auth_a) - 1] = '\0';

    WCHAR auth_w[MAX_KEY_LEN + 32];
    MultiByteToWideChar(CP_UTF8, 0, auth_a, -1, auth_w, MAX_KEY_LEN + 32);

    // make request
    char body[MAX_RESPONSE];
    DWORD body_len = 0;
    DWORD status = http_get(path_w, auth_w, body, MAX_RESPONSE, &body_len);

    dbglog("HTTP %lu", status);

    if (status == 0)
    {
        dbglog("request failed");
        return 0;
    }

    if (status == 401 && !g_auth_warned)
    {
        g_auth_warned = 1;
        dbglog("API key expired or invalid");
        MessageBoxA(NULL,
            "Your Morrenus API key is expired or invalid.\n"
            "Manifest downloads will fail until you update it.\n\n"
            "Get a new API key and run CloudFix again to update it.",
            "STFixer", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
        return 0;
    }

    if (status == 429)
    {
        dbglog("error: %s", body);

        if (strstr(body, "Daily") || strstr(body, "daily") ||
            strstr(body, "single manifest"))
        {
            // daily/manifest limit — verify with stats
            dbglog("daily limit hit, verifying with stats");
            do_stats_check();
            if (!g_daily_limit_hit) {
                // stats said we're ok? trust the 429 anyway for this call
                g_daily_limit_hit = 1;
                write_lockout();
                notify_daily_limit();
            }
        } else {
            // per-minute rate limit — exponential backoff
            g_last_429_tick = GetTickCount64();
            if (g_backoff_ms == 0)
                g_backoff_ms = BACKOFF_INITIAL_MS;
            else if (g_backoff_ms < BACKOFF_MAX_MS)
                g_backoff_ms = g_backoff_ms * 2;
            if (g_backoff_ms > BACKOFF_MAX_MS)
                g_backoff_ms = BACKOFF_MAX_MS;
            dbglog("rate limited, next backoff=%lu ms", g_backoff_ms);
        }
        return 0;
    }

    if (status != 200)
    {
        dbglog("error: %s", body);
        return 0;
    }

    // success — reset backoff
    g_backoff_ms = 0;

    dbglog("response: %.*s", (int)body_len, body);

    unsigned __int64 result = parse_request_code(body, body_len);
    dbglog("request_code=%llu", result);

    if (result != 0)
        cache_put(depot_id, manifest_id, result);

    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        ensure_cs();
        dbglog("stella_fallback loaded");
    }
    return TRUE;
}
