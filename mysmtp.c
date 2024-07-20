#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void init_ssl(void);
static void end_ssl(void);
static int connect_ssl(const char *hostname, const char *port);
static void close_ssl(void);
static void smtp_write(void);
static void smtp_writef(const char *format, ...);
static int smtp_read(void);
static void read_header(void);

static int verbose;

static SSL_CTX *ssl_ctx;
static char smtp_buffer[1024 * 8];
static int smtp_buffer_len;

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
connect_ssl(const char *hostname, const char *port)
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
  err = getaddrinfo(hostname, port, &hints, &result);
  if (err) {
    fprintf(stderr, "Failed to resolve server %s:%s : %s\n",
        hostname, port, gai_strerror(err));
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
    fprintf(stderr, "Failed to connect to %s:%s\n", hostname, port);
    return 1;
  }

  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL || SSL_set_fd(ssl, sock) == 0 || SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    close_ssl();
    return 1;
  }
  if (verbose)
    fprintf(stderr, "* Connected to %s:%s\n", hostname, port);
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
smtp_write(void)
{
  int n, written;
  if (verbose)
    fprintf(stderr, "> %.*s\n", smtp_buffer_len, smtp_buffer);

  if (smtp_buffer_len + 2 >= sizeof(smtp_buffer)) {
    fprintf(stderr, "Write failed, too large\n");
    exit(1);
  }
  smtp_buffer[smtp_buffer_len++] = '\r';
  smtp_buffer[smtp_buffer_len++] = '\n';

  written = 0;
  do {
    n = SSL_write(ssl, smtp_buffer + written, smtp_buffer_len - written);
    if (n <= 0) {
      fprintf(stderr, "Write failed\n");
      exit(1);
    }
    written += n;
  } while(written < smtp_buffer_len);
}

static void
smtp_writef(const char *format, ...)
{
  va_list args;
  assert(ssl);
  va_start(args, format);
  smtp_buffer_len = vsnprintf(smtp_buffer, sizeof(smtp_buffer), format, args);
  if (smtp_buffer_len >= sizeof(smtp_buffer)) {
    fprintf(stderr, "Write failed, too large\n");
    exit(1);
  }
  va_end(args);
  smtp_write();
}

static int
smtp_read(void)
{
  int line, n, i;
  assert(ssl);

  smtp_buffer_len = 0;
  line = 0;
  for (;;) {
    n = SSL_read(ssl, smtp_buffer + smtp_buffer_len, sizeof(smtp_buffer) - smtp_buffer_len);
    if (n <= 0) {
      fprintf(stderr, "Read failed\n");
      return -1;
    }
    smtp_buffer_len += n;
    for (i = line; i < smtp_buffer_len - 1; i++) {
      if (strncmp(smtp_buffer + i, "\r\n", 2) == 0) {
        smtp_buffer[i] = '\0';
        if (verbose)
          fprintf(stderr, "< %s\n", smtp_buffer + line);
        /* If last line of response, return status code. */
        if (i - line >= 3
        && isdigit(smtp_buffer[line]) && isdigit(smtp_buffer[line + 1]) && isdigit(smtp_buffer[line + 2])
        && (i - line == 3 || smtp_buffer[line + 3] == ' ')) {
          return 100 * (smtp_buffer[line] - '0')
            + 10 * (smtp_buffer[line + 1] - '0')
            + (smtp_buffer[line + 2] - '0');
        }
        line = i + 2;
      }
    }
  }
}

int
main(int argc, char *argv[])
{
  int status, line, i, intermediate;
  char line_buffer[1024];
  char *hostname, *port;
  hostname = "smtp.gmail.com";
  port = "465";
  line = 0;
  verbose = 1;
  intermediate = 0;

  init_ssl();
  connect_ssl(hostname, port);

  status = smtp_read();
  if (status / 100 != 2) {
    fprintf(stderr, "STMP failed to initialize with status %d.\n", status);
    goto smtp_error;
  }
  while (fgets(line_buffer, sizeof(line_buffer), stdin)) {
    line++;
    for (i = 0; line_buffer[i] != '\n' && line_buffer[i] != '\0'; i++);
    line_buffer[i] = '\0';
    if (line_buffer[0] == '.' && line_buffer[1] == '\0')
      intermediate = 0;
    smtp_writef("%s", line_buffer);
    if (!intermediate) {
      status = smtp_read();
      if (status / 100 == 3) {
        intermediate = 1;
      } else if (status / 100 != 2) {
        fprintf(stderr, "STMP failed on line %d with status %d.\n", line, status);
        goto smtp_error;
      }
    }
  }
  close_ssl();
  end_ssl();
  return 0;
smtp_error:
  close_ssl();
  end_ssl();
  return 1;
}
