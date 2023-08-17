#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_RCPTS 64
#define HEADER_BUFFER_SIZE (1024 * 16)

struct smtp_server {
  char *hostname, *port;
};

struct header_info {
  const char *from;
  const char *rcpts[MAX_RCPTS];
  int rcpt_count;
};

struct header_handler {
  const char *header;
  void (*handler)(const char *arg);
};

static void init_ssl(void);
static void end_ssl(void);
static int connect_ssl(const struct smtp_server server);
static void close_ssl(void);
static void smtp_write_raw(const char *bytes, int len);
static void smtp_write(const char *format, ...);
static int smtp_read(void);
static void from_header_handler(const char *arg);
static void to_header_handler(const char *arg);
static void read_header(void);

const static struct header_handler header_handlers[] = {
  {"From: ", from_header_handler},
  {"To: ", to_header_handler},
};

static int verbose;
static char header_buffer[HEADER_BUFFER_SIZE];
static char header_tokens[HEADER_BUFFER_SIZE];
static int header_len;
static struct header_info header_info;

static SSL_CTX *ssl_ctx;
static char buffer[1024 * 8];
static int buffer_len;

static int sock = -1;
static SSL *ssl;

static void
init_ssl(void)
{
  const SSL_METHOD *method;

  assert(ssl_ctx == NULL);

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  method = TLS_client_method();
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
}

static void
end_ssl(void)
{
  SSL_CTX_free(ssl_ctx);
  ssl_ctx = NULL;
}

static int
connect_ssl(const struct smtp_server server)
{
  struct addrinfo hints;
  struct addrinfo *result, *addr;
  int err;

  assert(sock == -1);
  assert(ssl == NULL);

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  err = getaddrinfo(server.hostname, server.port, &hints, &result);
  if (err) {
    fprintf(stderr, "Failed to resolve server %s:%s : %s\n",
        server.hostname, server.port, gai_strerror(err));
    return 1;
  }
  for (addr = result; addr; addr = addr->ai_next) {
    sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock < 0)
      continue;
    if (connect(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
      close(sock);
      continue;
    }
    break;
  }
  freeaddrinfo(result);
  if (addr == NULL) {
    fprintf(stderr, "Failed to connect to %s:%s\n", server.hostname, server.port);
    return 1;
  }

  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL || SSL_set_fd(ssl, sock) == 0 || SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    close_ssl();
    return 1;
  }
  if (verbose)
    fprintf(stderr, "* Connected to %s:%s\n", server.hostname, server.port);
  return 0;
}

static void
close_ssl(void)
{
  SSL_free(ssl);
  if (sock != -1)
    close(sock);
  ssl = NULL;
  sock = -1;
}

static void
smtp_write_raw(const char *bytes, int len)
{
  int written, c;
  assert(ssl);
  written = 0;
  do {
    c = SSL_write(ssl, bytes + written, len - written);
    if (c <= 0) {
      fprintf(stderr, "Write failed\n");
      exit(1);
    }
    written += c;
  } while(written < len);
}

static void
smtp_write(const char *format, ...)
{
  va_list args;
  int written, bytes;

  assert(ssl);

  va_start(args, format);
  buffer_len = vsnprintf(buffer, sizeof(buffer) - 1, format, args);
  if (buffer_len >= sizeof(buffer) - 1) {
    fprintf(stderr, "Write failed, too large\n");
    exit(1);
  }
  va_end(args);

  if (verbose)
    fprintf(stderr, "> %s\n", buffer);

  buffer[buffer_len++] = '\r';
  buffer[buffer_len++] = '\n';

  smtp_write_raw(buffer, buffer_len);
}

static int
smtp_read(void)
{
  int bytes, line, i;
  assert(ssl);

  buffer_len = 0;
  line = 0;
  for (;;) {
    bytes = SSL_read(ssl, buffer + buffer_len, sizeof(buffer) - buffer_len);
    if (bytes <= 0) {
      fprintf(stderr, "Read failed\n");
      return -1;
    }
    buffer_len += bytes;
    for (i = line; i < buffer_len - 1; i++) {
      if (strncmp(buffer + i, "\r\n", 2) == 0) {
        buffer[i] = '\0';
        if (verbose)
          fprintf(stderr, "< %s\n", buffer + line);
        /* If last line of response. */
        if (i - line >= 3
        && isdigit(buffer[line]) && isdigit(buffer[line + 1]) && isdigit(buffer[line + 2])
        && (i - line == 3 || buffer[line + 3] == ' ')) {
          return 100 * (buffer[line] - '0')
            + 10 * (buffer[line + 1] - '0')
            + (buffer[line + 2] - '0');
        }
        line = i + 2;
      }
    }
  }
}

static void
from_header_handler(const char *arg)
{
  if (header_info.from) {
    fprintf(stderr, "Only one from address allowed\n");
    exit(1);
  }
  header_info.from = arg;
}

static void
to_header_handler(const char *arg)
{
  if (header_info.rcpt_count >= MAX_RCPTS) {
    fprintf(stderr, "Max recipients exceeded (%d)\n", MAX_RCPTS);
    exit(1);
  }
  header_info.rcpts[header_info.rcpt_count++] = arg;
}

static void
read_header(void)
{
  int len, i, c;
  char *arg;
  memset(&header_info, 0, sizeof(header_info));
  header_len = 0;
  do {
    len = 0;
    while ( (c = fgetc(stdin)) != '\n') {
      if (c == EOF) {
        fprintf(stderr, "Incomplete header\n");
        exit(1);
      }
      if (header_len + len > sizeof(header_buffer) - 2) {
        fprintf(stderr, "Header too large\n");
        exit(1);
      }
      header_buffer[header_len + len++] = c;
    }

    memcpy(header_tokens + header_len, header_buffer + header_len, len);
    header_tokens[header_len + len] = '\0';

    for (i = 0; i < sizeof(header_handlers) / sizeof(header_handlers[0]); i++) {
      if (len >= strlen(header_handlers[i].header) + 1
      && strncmp(header_tokens + header_len, header_handlers[i].header,
          strlen(header_handlers[i].header)) == 0) {
        arg = strtok(header_tokens + header_len + strlen(header_handlers[i].header), " ");
        while (arg) {
          header_handlers[i].handler(arg);
          arg = strtok(NULL, " ");
        }
      }
    }

    header_len += len;
    header_buffer[header_len++] = '\r';
    header_buffer[header_len++] = '\n';
  } while (len > 0);
}

int
main(int argc, char **argv)
{
  struct smtp_server server;
  server.hostname = "smtp.gmail.com";
  server.port = "465";

  verbose = 1;

  read_header();
  if (header_info.from == NULL) {
    fprintf(stderr, "No from address\n");
    exit(1);
  }
  if (header_info.rcpt_count <= 0) {
    fprintf(stderr, "No recipients\n");
    exit(1);
  }

  init_ssl();
  connect_ssl(server);
  printf("RESPONSE CODE: %d\n", smtp_read());
  smtp_write("EHLO smtp.gmail.com");
  printf("RESPONSE CODE: %d\n", smtp_read());
  close_ssl();
  end_ssl();

  return 0;
}
