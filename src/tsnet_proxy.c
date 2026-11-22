//
// tsnet PoC: local SOCKS5 proxy layer for Moonlight streams (implementation)
//
// See tsnet_proxy.h for the design contract. All real functionality is
// POSIX-only; every other platform gets no-op stubs so the library keeps
// building and behaves exactly like upstream (fully direct) there.
//

#include "Limelight-internal.h"
#include "tsnet_proxy.h"

#if defined(LC_POSIX) && !defined(__vita__) && !defined(__WIIU__) && !defined(__3DS__) && !defined(NXDK)

#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

// ---- PoC configuration (compile-time defaults, runtime-overridable) -------
#ifndef TSNET_PROXY_DEFAULT_ENABLED
#define TSNET_PROXY_DEFAULT_ENABLED 1
#endif
// Fixed PoC port; overridable at runtime via LiTsnetSetProxyPort() for the
// future JNI bridge (tsnetbridge.socksPort()).
#ifndef TSNET_PROXY_DEFAULT_PORT
#define TSNET_PROXY_DEFAULT_PORT 1080
#endif
// Only proxy IPv4 destinations inside 100.64.0.0/10 (the tsnet/CGNAT range
// that a tailnet host lives in). Set to 0 to proxy every IPv4 destination.
#ifndef TSNET_PROXY_CGN_ONLY
#define TSNET_PROXY_CGN_ONLY 1
#endif
// Timeout for the TCP connect to the local proxy and for each handshake I/O.
#ifndef TSNET_SOCKS_CONNECT_TIMEOUT_MS
#define TSNET_SOCKS_CONNECT_TIMEOUT_MS 5000
#endif

// RFC 1928 constants
#define SOCKS5_VERSION             0x05
#define SOCKS5_METHOD_NO_AUTH      0x00
#define SOCKS5_CMD_CONNECT         0x01
#define SOCKS5_CMD_UDP_ASSOCIATE   0x03
#define SOCKS5_ATYP_IPV4           0x01
#define SOCKS5_ATYP_DOMAIN         0x03
#define SOCKS5_ATYP_IPV6           0x04
#define SOCKS5_REPLY_SUCCESS       0x00

// RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(16) + DST.PORT(2)
#define SOCKS5_UDP_HEADER_MAX      22
// RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2)
#define SOCKS5_UDP_HEADER_IPV4     10

#define TSNET_PROXY_LOOPBACK htonl(INADDR_LOOPBACK)

// Max concurrently proxied UDP sockets: video/audio/mic RTP + control ENet +
// RTSP ENet + up to 4 ConnectionTester probes. Overflowing entries stay direct.
#define TSNET_UDP_REGISTRY_SIZE 16

typedef struct _TSNET_UDP_ENTRY {
    SOCKET udpSocket;
    SOCKET controlSocket;
    struct sockaddr_in relayAddr;
} TSNET_UDP_ENTRY;

// NOTE: The enabled flag and port are read on streaming threads and written
// only via the setters below. The PoC contract is that setters are called
// before LiStartConnection() (from the future JNI bridge).
static bool tsnetProxyEnabled = TSNET_PROXY_DEFAULT_ENABLED;
static unsigned short tsnetProxyPort = TSNET_PROXY_DEFAULT_PORT;

static pthread_mutex_t tsnetMutex = PTHREAD_MUTEX_INITIALIZER;
static TSNET_UDP_ENTRY tsnetUdpRegistry[TSNET_UDP_REGISTRY_SIZE];
static bool tsnetRegistryInitialized;

// Scratch buffers for wrapped datagrams. Heap fallback for oversized packets.
#define TSNET_STACK_BUFFER_SIZE 2048

// ---- Configuration ----

void LiTsnetSetProxyEnabled(bool enabled) {
    tsnetProxyEnabled = enabled;
}

bool LiTsnetIsProxyEnabled(void) {
    return tsnetProxyEnabled;
}

void LiTsnetSetProxyPort(unsigned short port) {
    tsnetProxyPort = port;
}

unsigned short LiTsnetGetProxyPort(void) {
    return tsnetProxyPort;
}

// ---- Predicates ----

static bool tsnetIsCgnatAddressV4(const struct sockaddr_in* sin) {
    uint32_t addr = ntohl(sin->sin_addr.s_addr);
    return (addr & 0xFFC00000U) == 0x64400000U; // 100.64.0.0/10
}

bool TsnetShouldProxyAddress(const struct sockaddr_storage* addr) {
    if (!tsnetProxyEnabled) {
        return false;
    }
    if (addr == NULL || addr->ss_family != AF_INET) {
        return false;
    }
#if TSNET_PROXY_CGN_ONLY
    if (!tsnetIsCgnatAddressV4((const struct sockaddr_in*)addr)) {
        return false;
    }
#endif
    return true;
}

bool TsnetUdpProxyWanted(void) {
    return TsnetShouldProxyAddress(&RemoteAddr);
}

// ---- Registry ----

static void tsnetRegistryEnsureInitLocked(void) {
    int i;
    if (!tsnetRegistryInitialized) {
        for (i = 0; i < TSNET_UDP_REGISTRY_SIZE; i++) {
            tsnetUdpRegistry[i].udpSocket = INVALID_SOCKET;
            tsnetUdpRegistry[i].controlSocket = INVALID_SOCKET;
        }
        tsnetRegistryInitialized = true;
    }
}

static TSNET_UDP_ENTRY* tsnetRegistryFindLocked(SOCKET udpSocket) {
    int i;
    tsnetRegistryEnsureInitLocked();
    for (i = 0; i < TSNET_UDP_REGISTRY_SIZE; i++) {
        if (tsnetUdpRegistry[i].udpSocket == udpSocket && udpSocket != INVALID_SOCKET) {
            return &tsnetUdpRegistry[i];
        }
    }
    return NULL;
}

bool TsnetUdpSocketIsProxied(SOCKET s) {
    bool found;
    pthread_mutex_lock(&tsnetMutex);
    found = tsnetRegistryFindLocked(s) != NULL;
    pthread_mutex_unlock(&tsnetMutex);
    return found;
}

static void tsnetRegistryRemoveLocked(SOCKET udpSocket, SOCKET* outControlSocket) {
    TSNET_UDP_ENTRY* entry = tsnetRegistryFindLocked(udpSocket);
    *outControlSocket = INVALID_SOCKET;
    if (entry != NULL) {
        entry->udpSocket = INVALID_SOCKET;
        *outControlSocket = entry->controlSocket;
        entry->controlSocket = INVALID_SOCKET;
    }
}

void TsnetUdpSocketDetach(SOCKET udpSocket) {
    SOCKET controlSocket;
    if (udpSocket == INVALID_SOCKET) {
        return;
    }
    pthread_mutex_lock(&tsnetMutex);
    tsnetRegistryRemoveLocked(udpSocket, &controlSocket);
    pthread_mutex_unlock(&tsnetMutex);
    if (controlSocket != INVALID_SOCKET) {
        // Closing the TCP control connection tears down the UDP relay state
        // on the tsnet side too.
        close(controlSocket);
    }
}

// ---- SOCKS5 plumbing ----

static SOCKET tsnetConnectProxyTcp(int timeoutMs) {
    struct sockaddr_in proxyAddr;
    struct pollfd pfd;
    SOCKET s;
    int err;
    int flags;

    memset(&proxyAddr, 0, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = TSNET_PROXY_LOOPBACK;
    proxyAddr.sin_port = htons(tsnetProxyPort);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    flags = fcntl(s, F_GETFL, 0);
    if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
        err = LastSocketError();
        goto Failure;
    }

    err = connect(s, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr));
    if (err < 0 && LastSocketError() != EINPROGRESS) {
        err = LastSocketError();
        goto Failure;
    }
    if (err < 0) {
        // Wait for the non-blocking connect to complete
        pfd.fd = s;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        err = poll(&pfd, 1, timeoutMs);
        if (err == 0) {
            err = ETIMEDOUT;
            goto Failure;
        }
        else if (err < 0) {
            err = LastSocketError();
            goto Failure;
        }
        else {
            int soError = 0;
            socklen_t soLen = sizeof(soError);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soError, &soLen) < 0 || soError != 0) {
                err = soError != 0 ? soError : LastSocketFail();
                goto Failure;
            }
        }
    }

    // Restore blocking semantics for the SOCKS5 handshake
    fcntl(s, F_SETFL, flags);
    return s;

Failure:
    close(s);
    SetLastSocketError(err);
    return INVALID_SOCKET;
}

static void tsnetSetIoTimeoutMs(SOCKET s, int timeoutMs) {
    struct timeval val;
    val.tv_sec = timeoutMs / 1000;
    val.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&val, sizeof(val));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&val, sizeof(val));
}

static int tsnetSendAll(SOCKET s, const void* data, int len) {
    const char* p = (const char*)data;
    int remaining = len;
    while (remaining > 0) {
        int ret = (int)send(s, p, remaining, 0);
        if (ret < 0) {
            if (LastSocketError() == EINTR) {
                continue;
            }
            return -1;
        }
        p += ret;
        remaining -= ret;
    }
    return 0;
}

static int tsnetRecvAll(SOCKET s, void* data, int len) {
    char* p = (char*)data;
    int remaining = len;
    while (remaining > 0) {
        int ret = (int)recv(s, p, remaining, 0);
        if (ret < 0) {
            if (LastSocketError() == EINTR) {
                continue;
            }
            return -1;
        }
        else if (ret == 0) {
            SetLastSocketError(ECONNRESET);
            return -1;
        }
        p += ret;
        remaining -= ret;
    }
    return 0;
}

// Sends the no-auth greeting and verifies the server selects method 0x00.
static int tsnetSocks5Greeting(SOCKET ctl) {
    unsigned char greeting[3] = { SOCKS5_VERSION, 0x01, SOCKS5_METHOD_NO_AUTH };
    unsigned char response[2];

    if (tsnetSendAll(ctl, greeting, sizeof(greeting)) < 0) {
        return -1;
    }
    if (tsnetRecvAll(ctl, response, sizeof(response)) < 0) {
        return -1;
    }
    if (response[0] != SOCKS5_VERSION || response[1] != SOCKS5_METHOD_NO_AUTH) {
        // The proxy requires authentication (or is not a SOCKS5 server)
        SetLastSocketError(EACCES);
        return -1;
    }
    return 0;
}

// Reads VER/REP/RSV/ATYP followed by BND.ADDR/BND.PORT. Returns 0 on a
// successful reply, -1 otherwise. Fills *outAddr4/*outPort with the reply
// bound address (IPv4 replies only; anything else drains and reports
// loopback, since the tsnet relay is always local).
static int tsnetSocks5ReadReply(SOCKET ctl, unsigned char* outAddr4, unsigned short* outPort) {
    unsigned char replyHeader[4];
    unsigned char tail[16 + 2];
    unsigned char domainLength;
    const unsigned char* addrBytes;
    const unsigned char* portBytes;
    int addrLength;

    if (tsnetRecvAll(ctl, replyHeader, sizeof(replyHeader)) < 0) {
        return -1;
    }
    if (replyHeader[0] != SOCKS5_VERSION) {
        SetLastSocketError(EPROTO);
        return -1;
    }
    if (replyHeader[1] != SOCKS5_REPLY_SUCCESS) {
        // Non-zero REP: the proxy refused the request
        SetLastSocketError(ECONNREFUSED);
        return -1;
    }

    switch (replyHeader[3]) {
    case SOCKS5_ATYP_IPV4:
        addrLength = 4;
        break;
    case SOCKS5_ATYP_DOMAIN:
        if (tsnetRecvAll(ctl, &domainLength, sizeof(domainLength)) < 0) {
            return -1;
        }
        if (domainLength > (int)sizeof(tail) - 2) {
            // Malformed domain length; drain defensively and fail
            SetLastSocketError(EPROTO);
            return -1;
        }
        addrLength = domainLength;
        break;
    case SOCKS5_ATYP_IPV6:
        addrLength = 16;
        break;
    default:
        SetLastSocketError(EPROTO);
        return -1;
    }

    if (tsnetRecvAll(ctl, tail, addrLength + 2) < 0) {
        return -1;
    }

    // The relay endpoint is reached over loopback, so the reply's bound
    // address only matters for IPv4. 0.0.0.0 means "same address you're
    // connected to", which is 127.0.0.1 for us.
    if (outAddr4 != NULL && outPort != NULL) {
        if (replyHeader[3] == SOCKS5_ATYP_IPV4) {
            addrBytes = tail;
        }
        else {
            addrBytes = NULL;
        }
        portBytes = tail + addrLength;

        memset(outAddr4, 0, 4);
        if (addrBytes != NULL && (addrBytes[0] | addrBytes[1] | addrBytes[2] | addrBytes[3]) != 0) {
            memcpy(outAddr4, addrBytes, 4);
        }
        else {
            outAddr4[0] = 0x7F;
            outAddr4[1] = 0x00;
            outAddr4[2] = 0x00;
            outAddr4[3] = 0x01;
        }
        *outPort = (unsigned short)((portBytes[0] << 8) | portBytes[1]);
    }
    return 0;
}

// ---- TCP: SOCKS5 CONNECT ----

SOCKET TsnetConnectTcpProxy(const struct sockaddr_storage* dstaddr, unsigned short port, int timeoutSec) {
    const struct sockaddr_in* dst = (const struct sockaddr_in*)dstaddr;
    unsigned char request[10];
    int timeoutMs;
    SOCKET s;

    if (dstaddr == NULL || dstaddr->ss_family != AF_INET) {
        SetLastSocketError(EAFNOSUPPORT);
        return INVALID_SOCKET;
    }

    timeoutMs = timeoutSec > 0 ? timeoutSec * 1000 : TSNET_SOCKS_CONNECT_TIMEOUT_MS;

    s = tsnetConnectProxyTcp(timeoutMs);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    tsnetSetIoTimeoutMs(s, TSNET_SOCKS_CONNECT_TIMEOUT_MS);

    if (tsnetSocks5Greeting(s) < 0) {
        goto Failure;
    }

    // CONNECT with a raw IPv4 destination
    request[0] = SOCKS5_VERSION;
    request[1] = SOCKS5_CMD_CONNECT;
    request[2] = 0;
    request[3] = SOCKS5_ATYP_IPV4;
    memcpy(&request[4], &dst->sin_addr, 4);
    request[8] = (unsigned char)((port >> 8) & 0xFF);
    request[9] = (unsigned char)(port & 0xFF);

    if (tsnetSendAll(s, request, sizeof(request)) < 0) {
        goto Failure;
    }

    // Drain VER/REP/ATYP/BND.ADDR/BND.PORT
    if (tsnetSocks5ReadReply(s, NULL, NULL) < 0) {
        goto Failure;
    }

    // Restore plain blocking semantics like every other TCP socket in this
    // codebase; the stream code drives its own timeouts.
    tsnetSetIoTimeoutMs(s, 0);
    return s;

Failure: {
        int err = LastSocketError();
        close(s);
        SetLastSocketError(err);
    }
    return INVALID_SOCKET;
}

// ---- UDP: SOCKS5 UDP ASSOCIATE ----

static bool tsnetUdpAssociateInternal(SOCKET controlSocket, struct sockaddr_in* relayAddr) {
    unsigned char request[10] = { SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0, SOCKS5_ATYP_IPV4,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char relayAddrBytes[4];
    unsigned short relayPort;

    if (tsnetSocks5Greeting(controlSocket) < 0) {
        return false;
    }

    // UDP ASSOCIATE for any destination (0.0.0.0:0). The per-datagram
    // destinations are carried inside the SOCKS5 UDP header on the relay
    // socket instead.
    if (tsnetSendAll(controlSocket, request, sizeof(request)) < 0) {
        return false;
    }

    if (tsnetSocks5ReadReply(controlSocket, relayAddrBytes, &relayPort) < 0) {
        return false;
    }

    memset(relayAddr, 0, sizeof(*relayAddr));
    relayAddr->sin_family = AF_INET;
    memcpy(&relayAddr->sin_addr, relayAddrBytes, 4);
    relayAddr->sin_port = htons(relayPort);
    return true;
}

bool TsnetUdpSocketAssociate(SOCKET udpSocket) {
    SOCKET controlSocket;
    struct sockaddr_in relayAddr;
    TSNET_UDP_ENTRY* entry;
    SOCKET oldControlSocket = INVALID_SOCKET;

    if (udpSocket == INVALID_SOCKET) {
        return false;
    }

    controlSocket = tsnetConnectProxyTcp(TSNET_SOCKS_CONNECT_TIMEOUT_MS);
    if (controlSocket == INVALID_SOCKET) {
        return false;
    }

    tsnetSetIoTimeoutMs(controlSocket, TSNET_SOCKS_CONNECT_TIMEOUT_MS);
    if (!tsnetUdpAssociateInternal(controlSocket, &relayAddr)) {
        int err = LastSocketError();
        close(controlSocket);
        SetLastSocketError(err);
        return false;
    }
    tsnetSetIoTimeoutMs(controlSocket, 0);

    pthread_mutex_lock(&tsnetMutex);
    entry = tsnetRegistryFindLocked(udpSocket);
    if (entry != NULL) {
        // Re-association: replace the previous control connection
        oldControlSocket = entry->controlSocket;
        entry->controlSocket = controlSocket;
        entry->relayAddr = relayAddr;
    }
    else {
        int i;
        tsnetRegistryEnsureInitLocked();
        for (i = 0; i < TSNET_UDP_REGISTRY_SIZE; i++) {
            if (tsnetUdpRegistry[i].udpSocket == INVALID_SOCKET) {
                tsnetUdpRegistry[i].udpSocket = udpSocket;
                tsnetUdpRegistry[i].controlSocket = controlSocket;
                tsnetUdpRegistry[i].relayAddr = relayAddr;
                controlSocket = INVALID_SOCKET; // consumed
                break;
            }
        }
    }
    pthread_mutex_unlock(&tsnetMutex);

    if (controlSocket != INVALID_SOCKET) {
        // No free slot: the socket stays direct
        Limelog("Tsnet: UDP proxy registry full; leaving socket direct\n");
        close(controlSocket);
        return false;
    }
    if (oldControlSocket != INVALID_SOCKET) {
        close(oldControlSocket);
    }
    return true;
}

SOCKET TsnetUdpSocketCreateAndBind(void) {
    struct sockaddr_in loopbackAddr;
    SOCKET s;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    // The proxied socket must live on loopback: the tsnet SOCKS5 UDP relay
    // (127.0.0.1) delivers return traffic to whatever source address sent to
    // it, so a LAN-bound socket would never see the replies. The host sees
    // the tsnet egress address as our "local address" instead, which is
    // exactly what a tailnet session wants.
    memset(&loopbackAddr, 0, sizeof(loopbackAddr));
    loopbackAddr.sin_family = AF_INET;
    loopbackAddr.sin_addr.s_addr = TSNET_PROXY_LOOPBACK;
    if (bind(s, (struct sockaddr*)&loopbackAddr, sizeof(loopbackAddr)) < 0) {
        int err = LastSocketError();
        close(s);
        SetLastSocketError(err);
        return INVALID_SOCKET;
    }

    if (!TsnetUdpSocketAssociate(s)) {
        // The socket is loopback-bound and useless without a relay. Close it
        // so bindUdpSocket() can fall back to a fresh direct socket.
        close(s);
        return INVALID_SOCKET;
    }

    return s;
}

// A socket may only be lazily associated if it is unbound (kernel autobinds
// loopback for the first relay-bound sendto) or already bound to loopback.
// Sockets bound to a LAN address cannot receive relay return traffic.
static bool tsnetUdpCanLazyAssociate(SOCKET s) {
    struct sockaddr_storage localAddr;
    socklen_t addrLen = sizeof(localAddr);
    struct sockaddr_in* localAddrIn;

    if (getsockname(s, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        // No bind information available; assume it is usable. ENOTSOCK and
        // friends will be reported by the subsequent calls anyway.
        return true;
    }
    if (localAddr.ss_family != AF_INET) {
        return false;
    }
    localAddrIn = (struct sockaddr_in*)&localAddr;
    return localAddrIn->sin_addr.s_addr == TSNET_PROXY_LOOPBACK ||
           localAddrIn->sin_addr.s_addr == htonl(INADDR_ANY);
}

static bool tsnetGetRelayAddr(SOCKET s, struct sockaddr_in* relayAddr) {
    TSNET_UDP_ENTRY* entry;
    bool found = false;

    pthread_mutex_lock(&tsnetMutex);
    entry = tsnetRegistryFindLocked(s);
    if (entry != NULL) {
        *relayAddr = entry->relayAddr;
        found = true;
    }
    pthread_mutex_unlock(&tsnetMutex);
    return found;
}

// ---- Wrapped datagram I/O ----

int TsnetSendto(SOCKET s, const void* data, int len, const struct sockaddr* dst, SOCKADDR_LEN dstLen) {
    const struct sockaddr_in* dstIn;
    struct sockaddr_in relayAddr;
    unsigned char stackBuffer[TSNET_STACK_BUFFER_SIZE];
    unsigned char* wrapBuffer = stackBuffer;
    bool heapBuffer = false;
    int ret;

    if (len < 0) {
        SetLastSocketError(EINVAL);
        return -1;
    }

    if (!TsnetShouldProxyAddress((const struct sockaddr_storage*)dst)) {
        return (int)sendto(s, data, len, 0, dst, dstLen);
    }

    dstIn = (const struct sockaddr_in*)dst;

    if (!TsnetUdpSocketIsProxied(s)) {
        // Lazy association (used by ConnectionTester probes on unbound
        // sockets). Media sockets are pre-associated in bindUdpSocket().
        if (!tsnetUdpCanLazyAssociate(s) || !TsnetUdpSocketAssociate(s)) {
            // Proxy unavailable or unusable for this socket: direct fallback
            return (int)sendto(s, data, len, 0, dst, dstLen);
        }
    }

    if (!tsnetGetRelayAddr(s, &relayAddr)) {
        SetLastSocketError(EINVAL);
        return -1;
    }

    if (len + SOCKS5_UDP_HEADER_IPV4 > (int)sizeof(stackBuffer)) {
        wrapBuffer = (unsigned char*)malloc(len + SOCKS5_UDP_HEADER_IPV4);
        if (wrapBuffer == NULL) {
            SetLastSocketError(ENOMEM);
            return -1;
        }
        heapBuffer = true;
    }

    // SOCKS5 UDP request header: RSV(2)=0, FRAG=0, ATYP=IPv4, DST.ADDR, DST.PORT
    wrapBuffer[0] = 0;
    wrapBuffer[1] = 0;
    wrapBuffer[2] = 0;
    wrapBuffer[3] = SOCKS5_ATYP_IPV4;
    memcpy(&wrapBuffer[4], &dstIn->sin_addr, 4);
    // sin_port is already in network byte order
    memcpy(&wrapBuffer[8], &dstIn->sin_port, 2);
    memcpy(&wrapBuffer[SOCKS5_UDP_HEADER_IPV4], data, len);

    ret = (int)sendto(s, wrapBuffer, len + SOCKS5_UDP_HEADER_IPV4, 0,
                      (struct sockaddr*)&relayAddr, sizeof(relayAddr));

    if (heapBuffer) {
        free(wrapBuffer);
    }

    if (ret < 0) {
        return -1;
    }

    // Report the payload length like sendto() would for the unwrapped data
    return len;
}

int TsnetRecvfrom(SOCKET s, void* buffer, int size, struct sockaddr* outSrc, SOCKADDR_LEN* outSrcLen) {
    unsigned char stackBuffer[TSNET_STACK_BUFFER_SIZE];
    unsigned char* rawBuffer = stackBuffer;
    bool heapBuffer = false;
    struct sockaddr_storage relaySource;
    socklen_t relaySourceLen = sizeof(relaySource);
    int ret;
    int headerLength;
    int addrLength;
    int payloadLength;

    if (!TsnetUdpSocketIsProxied(s)) {
        return (int)recvfrom(s, buffer, size, 0, outSrc, outSrcLen);
    }

    // Receive with room for the largest possible SOCKS5 UDP header so the
    // payload never gets truncated by a short caller buffer.
    if (size + SOCKS5_UDP_HEADER_MAX > (int)sizeof(stackBuffer)) {
        rawBuffer = (unsigned char*)malloc(size + SOCKS5_UDP_HEADER_MAX);
        if (rawBuffer == NULL) {
            SetLastSocketError(ENOMEM);
            return -1;
        }
        heapBuffer = true;
    }

    ret = (int)recvfrom(s, rawBuffer, size + SOCKS5_UDP_HEADER_MAX, 0,
                        (struct sockaddr*)&relaySource, &relaySourceLen);

    if (ret < 0) {
        goto ExitError;
    }

    // Validate the SOCKS5 UDP reply header
    if (ret < SOCKS5_UDP_HEADER_IPV4 ||
            rawBuffer[0] != 0 || rawBuffer[1] != 0 || rawBuffer[2] != 0) {
        // Not a SOCKS5 datagram from the relay; drop it and report "no data"
        SetLastSocketError(EAGAIN);
        ret = -1;
        goto ExitError;
    }

    switch (rawBuffer[3]) {
    case SOCKS5_ATYP_IPV4:
        addrLength = 4;
        headerLength = SOCKS5_UDP_HEADER_IPV4;
        break;
    case SOCKS5_ATYP_DOMAIN:
        // SOCKS5 UDP replies carry the original sender address; a domain
        // address cannot be mapped into a sockaddr, so drop such packets.
        SetLastSocketError(EAGAIN);
        ret = -1;
        goto ExitError;
    case SOCKS5_ATYP_IPV6:
        addrLength = 16;
        headerLength = 3 + 1 + addrLength + 2;
        break;
    default:
        SetLastSocketError(EAGAIN);
        ret = -1;
        goto ExitError;
    }

    if (ret < headerLength) {
        SetLastSocketError(EAGAIN);
        ret = -1;
        goto ExitError;
    }

    payloadLength = ret - headerLength;
    if (payloadLength > size) {
        // Should be impossible given the receive sizing above
        SetLastSocketError(EMSGSIZE);
        ret = -1;
        goto ExitError;
    }

    memmove(buffer, rawBuffer + headerLength, payloadLength);

    // Report the ORIGINAL sender (from the SOCKS5 header), not the relay
    // address. This is what keeps ENet's peer address tracking and the
    // Sunshine endpoint logic sane behind the relay.
    if (outSrc != NULL && outSrcLen != NULL) {
        if (rawBuffer[3] == SOCKS5_ATYP_IPV4 && *outSrcLen >= (SOCKADDR_LEN)sizeof(struct sockaddr_in)) {
            struct sockaddr_in* srcIn = (struct sockaddr_in*)outSrc;
            memset(srcIn, 0, sizeof(*srcIn));
            srcIn->sin_family = AF_INET;
            memcpy(&srcIn->sin_addr, &rawBuffer[4], 4);
            memcpy(&srcIn->sin_port, &rawBuffer[4 + addrLength], 2);
            *outSrcLen = sizeof(*srcIn);
        }
        else {
            *outSrcLen = 0;
        }
    }

    if (heapBuffer) {
        free(rawBuffer);
    }
    return payloadLength;

ExitError:
    if (heapBuffer) {
        free(rawBuffer);
    }
    return ret;
}

#else // Non-POSIX or niche platform: fully direct stubs

void LiTsnetSetProxyEnabled(bool enabled) {
    (void)enabled;
}

bool LiTsnetIsProxyEnabled(void) {
    return false;
}

void LiTsnetSetProxyPort(unsigned short port) {
    (void)port;
}

unsigned short LiTsnetGetProxyPort(void) {
    return 0;
}

bool TsnetShouldProxyAddress(const struct sockaddr_storage* addr) {
    (void)addr;
    return false;
}

bool TsnetUdpProxyWanted(void) {
    return false;
}

SOCKET TsnetConnectTcpProxy(const struct sockaddr_storage* dstaddr, unsigned short port, int timeoutSec) {
    (void)dstaddr;
    (void)port;
    (void)timeoutSec;
    return INVALID_SOCKET;
}

SOCKET TsnetUdpSocketCreateAndBind(void) {
    return INVALID_SOCKET;
}

bool TsnetUdpSocketAssociate(SOCKET udpSocket) {
    (void)udpSocket;
    return false;
}

bool TsnetUdpSocketIsProxied(SOCKET s) {
    (void)s;
    return false;
}

void TsnetUdpSocketDetach(SOCKET udpSocket) {
    (void)udpSocket;
}

// On stub platforms the wrappers are pure passthroughs, so callers behave
// exactly like the unpatched upstream code.
int TsnetSendto(SOCKET s, const void* data, int len, const struct sockaddr* dst, SOCKADDR_LEN dstLen) {
    return (int)sendto(s, data, len, 0, dst, dstLen);
}

int TsnetRecvfrom(SOCKET s, void* buffer, int size, struct sockaddr* outSrc, SOCKADDR_LEN* outSrcLen) {
    return (int)recvfrom(s, buffer, size, 0, outSrc, outSrcLen);
}

#endif
