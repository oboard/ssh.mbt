/*
 * Socket FFI implementation for Windows (MinGW compatible)
 * Provides basic TCP socket functionality without async
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <moonbit.h>

/* Global debug flag controlled by MoonBit layer */
int moonssh_debug = 0;

/* FFI: called from MoonBit to set debug flag */
MOONBIT_FFI_EXPORT
void moonbit_set_moonssh_debug(int32_t val) {
    moonssh_debug = val;
}

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

static int winsock_initialized = 0;
static HMODULE winsock_module = 0;

typedef int (WSAAPI *WSAStartupFn)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *SocketFn)(int, int, int);
typedef int (WSAAPI *ConnectFn)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *SendFn)(SOCKET, const char *, int, int);
typedef int (WSAAPI *RecvFn)(SOCKET, char *, int, int);
typedef int (WSAAPI *CloseSocketFn)(SOCKET);
typedef unsigned long (WSAAPI *InetAddrFn)(const char *);
typedef struct hostent *(WSAAPI *GetHostByNameFn)(const char *);
typedef int (WSAAPI *WSAGetLastErrorFn)(void);
typedef int (WSAAPI *SetSockOptFn)(SOCKET, int, int, const char *, int);

static WSAStartupFn p_WSAStartup = 0;
static SocketFn p_socket = 0;
static ConnectFn p_connect = 0;
static SendFn p_send = 0;
static RecvFn p_recv = 0;
static CloseSocketFn p_closesocket = 0;
static InetAddrFn p_inet_addr = 0;
static GetHostByNameFn p_gethostbyname = 0;
static WSAGetLastErrorFn p_WSAGetLastError = 0;
static SetSockOptFn p_setsockopt = 0;

static int load_winsock(void) {
    if (winsock_module) {
        return 0;
    }
    winsock_module = LoadLibraryA("ws2_32.dll");
    if (!winsock_module) {
        return -1;
    }
    p_WSAStartup = (WSAStartupFn)GetProcAddress(winsock_module, "WSAStartup");
    p_socket = (SocketFn)GetProcAddress(winsock_module, "socket");
    p_connect = (ConnectFn)GetProcAddress(winsock_module, "connect");
    p_send = (SendFn)GetProcAddress(winsock_module, "send");
    p_recv = (RecvFn)GetProcAddress(winsock_module, "recv");
    p_closesocket = (CloseSocketFn)GetProcAddress(winsock_module, "closesocket");
    p_inet_addr = (InetAddrFn)GetProcAddress(winsock_module, "inet_addr");
    p_gethostbyname = (GetHostByNameFn)GetProcAddress(winsock_module, "gethostbyname");
    p_WSAGetLastError = (WSAGetLastErrorFn)GetProcAddress(winsock_module, "WSAGetLastError");
    p_setsockopt = (SetSockOptFn)GetProcAddress(winsock_module, "setsockopt");
    if (!p_WSAStartup || !p_socket || !p_connect || !p_send || !p_recv ||
        !p_closesocket || !p_inet_addr || !p_gethostbyname ||
        !p_WSAGetLastError || !p_setsockopt) {
        return -1;
    }
    return 0;
}

static uint16_t socket_htons(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static int send_all(SOCKET sock, const char *buffer, int data_len) {
    if (!p_send && load_winsock() != 0) {
        return -1;
    }
    int sent = 0;
    while (sent < data_len) {
        int result = p_send(sock, buffer + sent, data_len - sent, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += result;
    }
    return sent;
}

/*
 * Initialize Winsock2
 * Returns 0 on success, error code otherwise
 */
int socket_init(void) {
    if (winsock_initialized) {
        return 0;
    }
    if (load_winsock() != 0) {
        return -1;
    }

    WSADATA wsa_data;
    int result = p_WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result == 0) {
        winsock_initialized = 1;
    }
    return result;
}

/*
 * Create a TCP socket
 * Returns socket handle on success, -1 on error
 */
int socket_create(void) {
    if (!p_socket && load_winsock() != 0) {
        return -1;
    }
    SOCKET sock = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }
    return (int)sock;
}

/*
 * Connect to a remote host
 * Returns 0 on success, error code otherwise
 */
int socket_connect(int handle, moonbit_string_t host_str, int port) {
    // Extract host string from MoonBit string
    int host_len = Moonbit_array_length(host_str);
    char *host = (char *)malloc(host_len + 1);
    if (!host) {
        return -1;
    }

    // Copy string data (MoonBit strings are UTF-16 on Windows)
    const uint16_t *src = host_str;
    for (int i = 0; i < host_len; i++) {
        host[i] = (char)src[i];  // Simple ASCII conversion
    }
    host[host_len] = '\0';

    // Setup address structure
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = socket_htons((uint16_t)port);

    // Convert hostname to IP address
    addr.sin_addr.s_addr = p_inet_addr(host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        // Try resolving as hostname
        struct hostent *he = p_gethostbyname(host);
        free(host);
        if (!he) {
            return p_WSAGetLastError();
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        free(host);
    }

    // Connect
    SOCKET sock = (SOCKET)handle;
    int result = p_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result == SOCKET_ERROR) {
        return p_WSAGetLastError();
    }

    return 0;
}

/*
 * Send data through socket
 * Returns number of bytes sent, or -1 on error
 */
int socket_send(int handle, moonbit_string_t data_str) {
    int data_len = Moonbit_array_length(data_str);
    const uint16_t *src = data_str;

    // Convert to ASCII buffer
    char *buffer = (char *)malloc(data_len);
    if (!buffer) {
        return -1;
    }

    for (int i = 0; i < data_len; i++) {
        buffer[i] = (char)src[i];
    }

    SOCKET sock = (SOCKET)handle;
    int result = send_all(sock, buffer, data_len);
    free(buffer);

    return result;
}

int socket_send_bytes(int handle, moonbit_bytes_t data, int data_len) {
    SOCKET sock = (SOCKET)handle;
    const char *buffer = (const char *)data;
    return send_all(sock, buffer, data_len);
}

/*
 * Receive data from socket
 * Returns number of bytes received, 0 on connection close, -1 on error
 */
int socket_recv(int handle, moonbit_bytes_t buffer, int offset, int size) {
    SOCKET sock = (SOCKET)handle;
    uint8_t *buf_ptr = (uint8_t *)buffer;

    if (!p_recv && load_winsock() != 0) {
        return -1;
    }
    int result = p_recv(sock, (char *)(buf_ptr + offset), size, 0);
    if (result == SOCKET_ERROR) {
        return -1;
    }

    return result;
}

/*
 * Close a socket
 */
void socket_close(int handle) {
    if (!p_closesocket && load_winsock() != 0) {
        return;
    }
    SOCKET sock = (SOCKET)handle;
    p_closesocket(sock);
}

/*
 * Set TCP_NODELAY (disable Nagle's algorithm) on the socket.
 * Returns 0 on success, -1 on error.
 */
int socket_set_nodelay(int handle) {
    if (!p_setsockopt && load_winsock() != 0) {
        return -1;
    }
    char flag = 1;
    SOCKET sock = (SOCKET)handle;
    return p_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

#else
// Unix/Linux implementation placeholder
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

static int send_all(int sock, const char *buffer, int data_len) {
    int sent = 0;
    while (sent < data_len) {
        int result = (int)send(sock, buffer + sent, (size_t)(data_len - sent), 0);
        if (result <= 0) {
            return -1;
        }
        sent += result;
    }
    return sent;
}

static char *moonbit_string_to_ascii(moonbit_string_t s, int *len_out) {
    int len = Moonbit_array_length(s);
    char *out = (char *)malloc((size_t)len + 1);
    if (!out) {
        return 0;
    }
    const uint16_t *src = s;
    for (int i = 0; i < len; i++) {
        out[i] = (char)src[i];
    }
    out[len] = '\0';
    if (len_out) {
        *len_out = len;
    }
    return out;
}

int socket_init(void) {
    return 0;  // No initialization needed on Unix
}

int socket_create(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int socket_connect(int handle, moonbit_string_t host_str, int port) {
    int host_len = 0;
    char *host = moonbit_string_to_ascii(host_str, &host_len);
    (void)host_len;
    if (!host) {
        return -1;
    }

    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%d", port);

    struct addrinfo hints;
    struct addrinfo *result = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port_buf, &hints, &result);
    free(host);
    if (rc != 0) {
        return rc;
    }

    int connected = -1;
    for (struct addrinfo *rp = result; rp != 0; rp = rp->ai_next) {
        if (connect(handle, rp->ai_addr, rp->ai_addrlen) == 0) {
            connected = 0;
            break;
        }
    }
    freeaddrinfo(result);
    return connected;
}

int socket_send(int handle, moonbit_string_t data_str) {
    int data_len = 0;
    char *buffer = moonbit_string_to_ascii(data_str, &data_len);
    if (!buffer) {
        return -1;
    }
    int result = send_all(handle, buffer, data_len);
    free(buffer);
    return result;
}

int socket_send_bytes(int handle, moonbit_bytes_t data, int data_len) {
    const char *buffer = (const char *)data;
    if (moonssh_debug) {
        fprintf(stderr, "socket_send_bytes: sending %d bytes on fd=%d\n", data_len, handle);
        // Print first 16 bytes of payload for debugging
        if (data_len > 0 && data_len <= 64) {
            fprintf(stderr, "socket_send_bytes: data dump:");
            for (int i = 0; i < data_len; i++) {
                fprintf(stderr, " %02x", (unsigned char)buffer[i]);
            }
            fprintf(stderr, "\n");
        } else if (data_len > 64) {
            fprintf(stderr, "socket_send_bytes: data dump (first 32):");
            for (int i = 0; i < 32; i++) {
                fprintf(stderr, " %02x", (unsigned char)buffer[i]);
            }
            fprintf(stderr, " ...\n");
        }
    }
    return send_all(handle, buffer, data_len);
}

int socket_recv(int handle, moonbit_bytes_t buffer, int offset, int size) {
    uint8_t *buf_ptr = (uint8_t *)buffer;
    int result = (int)recv(handle, (char *)(buf_ptr + offset), (size_t)size, 0);
    if (result == 0) {
        /* Connection closed gracefully by peer */
        if (moonssh_debug) fprintf(stderr, "socket_recv: connection closed (fd=%d)\n", handle);
    } else if (result < 0) {
        /* Error occurred */
        if (moonssh_debug) fprintf(stderr, "socket_recv: error %d (errno=%d: %s) on fd=%d\n",
                result, errno, strerror(errno), handle);
    } else if (result > 0 && result <= 64) {
        /* Dump received data for small reads */
        if (moonssh_debug) {
            fprintf(stderr, "socket_recv: got %d bytes on fd=%d: ", result, handle);
            for (int i = 0; i < result; i++) {
                fprintf(stderr, "%02x ", (unsigned char)(buf_ptr[offset + i]));
            }
            fprintf(stderr, "\n");
        }
    }
    return result;
}

void socket_close(int handle) {
    close(handle);
}

/*
 * Set TCP_NODELAY (disable Nagle's algorithm) on the socket.
 * Returns 0 on success, -1 on error.
 */
int socket_set_nodelay(int handle) {
    int flag = 1;
    return setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
}

#endif
