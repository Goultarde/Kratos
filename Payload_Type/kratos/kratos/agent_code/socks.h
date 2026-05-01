#pragma once
#ifdef INCLUDE_CMD_SOCKS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

void socks_init(void);
void socks_shutdown(void);

// Called from main.c for each datagram received from Mythic
void socks_handle_incoming(int server_id, const char *data_b64, int exit_flag);

// Called from main.c to flush outbound datagrams to Mythic
// Envoie un post_response avec "responses":[] et "socks":[...]
void socks_send_pending(void);

#endif // INCLUDE_CMD_SOCKS
