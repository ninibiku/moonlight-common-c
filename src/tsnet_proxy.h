//
// tsnet PoC: local SOCKS5 proxy layer for Moonlight streams
//
// Tunnels the C-layer streaming traffic (TCP control plane + UDP media plane,
// including the ENet control/RTSP sockets) through the SOCKS5 server provided
// by the in-process tsnet AAR (default 127.0.0.1:1080).
//
// Design rules:
//  - Only destinations matching TsnetShouldProxyAddress() are proxied
//    (default: IPv4 literals inside 100.64.0.0/10, the tsnet/CGNAT range).
//    Everything else is left 100% direct.
//  - Every proxy attempt falls back to the original direct behavior if the
//    proxy is unreachable or the SOCKS5 handshake fails, so enabling this
//    code can never make a non-tsnet session worse than before.
//  - No existing function signature changed; callers keep using their
//    original socket APIs via the Tsnet* wrappers.
//

#pragma once

#include "PlatformSockets.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---- Runtime configuration ------------------------------------------------
// Defaults are compile-time (see tsnet_proxy.c). These setters exist so a
// future JNI bridge (or tests) can flip the proxy on/off and point it at a
// dynamic tsnet SOCKS5 port without rebuilding.
void LiTsnetSetProxyEnabled(bool enabled);
bool LiTsnetIsProxyEnabled(void);
void LiTsnetSetProxyPort(unsigned short port);
unsigned short LiTsnetGetProxyPort(void);

// ---- Predicates -------------------------------------------------------------
// True when this destination address should be tunneled (proxy enabled +
// IPv4 + inside the configured proxied range).
bool TsnetShouldProxyAddress(const struct sockaddr_storage* addr);

// True when new UDP sockets for the current session should be proxied
// (checks the global RemoteAddr). Used by bindUdpSocket() and the ENet
// socket hooks.
bool TsnetUdpProxyWanted(void);

// ---- TCP --------------------------------------------------------------------
// Establishes a SOCKS5 TCP CONNECT tunnel to dstaddr:port and returns the
// connected socket (plain send/recv usable by the original code). Returns
// INVALID_SOCKET with the socket error set on failure; caller falls back to
// a direct connection.
SOCKET TsnetConnectTcpProxy(const struct sockaddr_storage* dstaddr, unsigned short port, int timeoutSec);

// ---- UDP registry -----------------------------------------------------------
// Creates an AF_INET UDP socket bound to 127.0.0.1:0 and registers it with a
// SOCKS5 UDP ASSOCIATE. Returns INVALID_SOCKET on failure (caller falls back
// to the direct bindUdpSocket() path).
SOCKET TsnetUdpSocketCreateAndBind(void);

// Registers an existing (unbound or loopback-bound) UDP socket with a SOCKS5
// UDP ASSOCIATE. Returns false on failure; the socket stays direct.
bool TsnetUdpSocketAssociate(SOCKET udpSocket);

// True if this UDP socket fd is currently proxied (cheap registry lookup).
bool TsnetUdpSocketIsProxied(SOCKET udpSocket);

// Drops the UDP ASSOCIATE state for this socket and closes the TCP control
// connection. No-op for unregistered sockets. Must be called before close().
void TsnetUdpSocketDetach(SOCKET udpSocket);

// ---- Wrapped datagram I/O ----------------------------------------------------
// Drop-in replacements for sendto()/recvfrom() on sockets that may be
// SOCKS5-proxied. For unregistered sockets they are plain sendto()/recvfrom().
//
// TsnetSendto: wraps the payload in a SOCKS5 UDP header (RSV=0, FRAG=0,
// ATYP=IPv4, DST=<dst>) and sends it to the relay address. Returns the
// payload length on success, -1 with the socket error set on failure.
// Non-proxied destinations go out as a direct sendto().
//
// TsnetRecvfrom: receives one relay datagram, strips the SOCKS5 UDP header
// and reports the ORIGINAL sender (from the header) in outSrc when
// requested. Returns the payload length, or -1 with the socket error set
// exactly like recvfrom() (malformed relay packets are consumed and reported
// as EAGAIN).
int TsnetSendto(SOCKET s, const void* data, int len, const struct sockaddr* dst, SOCKADDR_LEN dstLen);
int TsnetRecvfrom(SOCKET s, void* buffer, int size, struct sockaddr* outSrc, SOCKADDR_LEN* outSrcLen);

#ifdef __cplusplus
}
#endif
