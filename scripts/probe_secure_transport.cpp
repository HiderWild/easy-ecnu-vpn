#include <Security/SecureTransport.h>
#include <Security/Security.h>

#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

struct Io {
  int fd = -1;
};

static OSStatus rcb(SSLConnectionRef c, void *d, size_t *n) {
  auto *io = reinterpret_cast<Io *>(const_cast<void *>(c));
  size_t req = *n;
  *n = 0;
  ssize_t r;
  do {
    r = recv(io->fd, d, req, 0);
  } while (r < 0 && errno == EINTR);
  if (r > 0) {
    *n = static_cast<size_t>(r);
    return noErr;
  }
  if (r == 0)
    return errSSLClosedGraceful;
  if (errno == EAGAIN || errno == EWOULDBLOCK)
    return errSSLWouldBlock;
  return errSSLClosedAbort;
}

static OSStatus wcb(SSLConnectionRef c, const void *d, size_t *n) {
  auto *io = reinterpret_cast<Io *>(const_cast<void *>(c));
  size_t req = *n;
  *n = 0;
  ssize_t w;
  do {
    w = send(io->fd, d, req, 0);
  } while (w < 0 && errno == EINTR);
  if (w > 0) {
    *n = static_cast<size_t>(w);
    return noErr;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK)
    return errSSLWouldBlock;
  return errSSLClosedAbort;
}

static int open_socket(const char *host) {
  addrinfo h{}, *res = nullptr;
  h.ai_socktype = SOCK_STREAM;
  h.ai_family = AF_UNSPEC;
  if (getaddrinfo(host, "443", &h, &res) != 0)
    return -1;
  int fd = -1;
  for (auto p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0)
      continue;
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static void try_cfg(const char *label, const char *host, bool break_auth,
                    bool set_max) {
  int fd = open_socket(host);
  printf("\n=== %s host=%s fd=%d ===\n", label, host, fd);
  if (fd < 0) {
    perror("connect");
    return;
  }
  timeval tv{15, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  int nosig = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosig, sizeof(nosig));
  Io io{fd};
  SSLContextRef ctx =
      SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
  OSStatus st = SSLSetProtocolVersionMin(ctx, kTLSProtocol12);
  printf("min=%d\n", static_cast<int>(st));
  if (set_max) {
    st = SSLSetProtocolVersionMax(ctx, kTLSProtocol12);
    printf("max=%d\n", static_cast<int>(st));
  }
  st = SSLSetIOFuncs(ctx, rcb, wcb);
  printf("io=%d\n", static_cast<int>(st));
  st = SSLSetConnection(ctx, &io);
  printf("conn=%d\n", static_cast<int>(st));
  st = SSLSetPeerDomainName(ctx, host, strlen(host));
  printf("sni=%d\n", static_cast<int>(st));
  if (break_auth) {
    st = SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
    printf("break=%d\n", static_cast<int>(st));
  }
  for (int i = 0; i < 16; ++i) {
    st = SSLHandshake(ctx);
    printf("hs%d=%d\n", i, static_cast<int>(st));
    if (st == noErr) {
      printf("OK\n");
      break;
    }
    if (st == errSSLWouldBlock)
      continue;
    if (st == errSSLServerAuthCompleted)
      continue;
    printf("FAIL\n");
    break;
  }
  SSLClose(ctx);
  CFRelease(ctx);
  close(fd);
}

int main() {
  try_cfg("exv-like", "vpn-cn.ecnu.edu.cn", true, false);
  try_cfg("no-break", "vpn-cn.ecnu.edu.cn", false, false);
  try_cfg("min-max", "vpn-cn.ecnu.edu.cn", true, true);
  return 0;
}
