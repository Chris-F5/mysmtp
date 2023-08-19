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

#define MAX_RCPTS 64
#define HEADER_BUFFER_SIZE (1024 * 16)

struct account_config {
  const char *email;
  const char *pass;
  const char *smtp_hostname;
  const char *smtp_port;
};

struct header_info {
  const char *from;
  const char *rcpts[MAX_RCPTS];
  int rcpt_count;
};

struct header_handler {
  const char *header;
  void (*handler)(char *arg);
};

static void init_ssl(void);
static void end_ssl(void);
static int connect_ssl(const char *hostname, const char *port);
static void close_ssl(void);
static void smtp_write(void);
static void smtp_writef(const char *format, ...);
static int smtp_read(void);
static void from_header_handler(char *arg);
static void to_header_handler(char *arg);
static void read_header(void);

#include "config.h"

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

static void
from_header_handler(char *arg)
{
  char *email, *end;
  if (header_info.from) {
    fprintf(stderr, "Only one from address allowed\n");
    exit(1);
  }
  email = strchr(arg, '<') + 1;
  if (email) {
    end = strchr(email, '>');
    if (end == NULL) {
      fprintf(stderr, "From email does not close angle brackets\n");
      exit(1);
    }
    *end = '\0';
    header_info.from = email;
  } else {
    header_info.from = arg;
  }
}

static void
to_header_handler(char *arg)
{
  const char *addr;
  addr = strtok(arg, " ");
  while (addr) {
    if (header_info.rcpt_count >= MAX_RCPTS) {
      fprintf(stderr, "Max recipients exceeded (%d)\n", MAX_RCPTS);
      exit(1);
    }
    header_info.rcpts[header_info.rcpt_count++] = addr;
    addr = strtok(NULL, " ");
  }
}

static void
read_header(void)
{
  int c, i, line;
  header_buffer[0] = header_tokens[0] = '\0';
  header_len = 0;
  line = 0;
  for (;;) {
    c = fgetc(stdin);
    if (c == EOF) {
      fprintf(stderr, "Incomplete header\n");
      exit(1);
    }
    if (header_len >= HEADER_BUFFER_SIZE) {
      fprintf(stderr, "Header too large\n");
      exit(1);
    }
    if (line == header_len && c == '.') {
      header_buffer[header_len] = header_tokens[header_len] = '.';
      header_len++;
      line++;
    }
    if (c == '\n') {
      if (header_len == 0 || header_buffer[header_len - 1] == '\0') {
        break;
      }
      header_buffer[header_len] = header_tokens[header_len] = '\0';
      header_len++;
      for (i = 0; i < sizeof(header_handlers) / sizeof(header_handlers[0]); i++) {
        if (strncmp(header_tokens + line, header_handlers[i].header, 
              strlen(header_handlers[i].header)) == 0) {
          header_handlers[i].handler(header_tokens + line + strlen(header_handlers[i].header));
          break;
        }
      }
      line = header_len;
    } else {
      header_buffer[header_len] = header_tokens[header_len] = c;
      header_len++;
    }
  }
}

int
main(int argc, char **argv)
{
  int i, status, c;
  const struct account_config *account;
  char auth[192];
  char auth_encoded[257];

  verbose = 1;
  read_header();

  if (header_info.from == NULL) {
    fprintf(stderr, "No from address\n");
    return 1;
  }
  if (header_info.rcpt_count <= 0) {
    fprintf(stderr, "No recipients\n");
    return 1;
  }

  account = NULL;
  for (i = 0; i < sizeof(accounts) / sizeof(accounts[0]); i++)
    if (strcmp(accounts[i].email, header_info.from) == 0) {
      account = &accounts[i];
      break;
    }
  if (account == NULL) {
    fprintf(stderr, "No config for account '%s'\n", header_info.from);
    return 1;
  }

  if (strlen(account->email) + strlen(account->pass) + 2 > sizeof(auth)) {
    fprintf(stderr, "Auth too large\n");
    return 1;
  }
  auth[0] = '\0';
  memcpy(auth + 1, account->email, strlen(account->email));
  auth[strlen(account->email) + 1] = '\0';
  memcpy(auth + strlen(account->email) + 2, account->pass, strlen(account->pass));
  EVP_EncodeBlock((unsigned char *)auth_encoded, (const unsigned char *)auth,
      strlen(account->email) + strlen(account->pass) + 2);

  init_ssl();
  connect_ssl(account->smtp_hostname, account->smtp_port);
  if ( (status = smtp_read()) / 100 != 2) {
    fprintf(stderr, "SMTP session initiation failed (%d)\n", status);
    goto smtp_error;
  }
  smtp_writef("EHLO localhost");
  if ( (status = smtp_read()) / 100 != 2) {
    fprintf(stderr, "SMTP client initiation failed (%d)\n", status);
    goto smtp_error;
  }
  smtp_writef("AUTH PLAIN %s", auth_encoded);
  if ( (status = smtp_read()) / 100 != 2) {
    fprintf(stderr, "SMTP authentication failed (%d)\n", status);
    goto smtp_error;
  }
  smtp_writef("MAIL FROM:<%s>", account->email);
  if ( (status = smtp_read()) / 100 != 2) {
    fprintf(stderr, "SMTP sender identification failed (%d)\n", status);
    goto smtp_error;
  }
  for (i = 0; i < header_info.rcpt_count; i++) {
    smtp_writef("RCPT TO:<%s>", header_info.rcpts[i]);
    if ( (status = smtp_read()) / 100 != 2) {
      fprintf(stderr, "SMTP receiver information failed (%d)\n", status);
      goto smtp_error;
    }
  }
  smtp_writef("DATA");
  if ( (status = smtp_read()) / 100 != 3) {
    fprintf(stderr, "SMTP data transfer initiate failed (%d)\n", status);
    goto smtp_error;
  }
  i = 0;
  while (i < header_len) {
    smtp_writef("%s", header_buffer + i);
    i += strlen(header_buffer + i) + 1;
  }
  smtp_writef("");
  smtp_buffer_len = 0;
  while ( (c = fgetc(stdin)) != EOF) {
    if (smtp_buffer_len >= sizeof(smtp_buffer)) {
      fprintf(stderr, "Mail data line too long\n");
      exit(1);
    }
    if (smtp_buffer_len == 0 && c == '.')
      smtp_buffer[smtp_buffer_len++] = '.';
    if (c == '\n' || (c == EOF && smtp_buffer_len)) {
      smtp_write();
      smtp_buffer_len = 0;
    } else {
      smtp_buffer[smtp_buffer_len++] = c;
    }
  }
  if (smtp_buffer_len)
    smtp_write();
  smtp_writef(".");
  if ( (status = smtp_read()) / 100 != 2) {
    fprintf(stderr, "SMTP data transfer failed (%d)\n", status);
    goto smtp_error;
  }
  smtp_writef("QUIT");
  if ( (status = smtp_read()) / 100 != 2) {
    fprintf(stderr, "SMTP quit failed (%d)\n", status);
    goto smtp_error;
  }
  close_ssl();
  end_ssl();
  return 0;
smtp_error:
  close_ssl();
  end_ssl();
  return 1;
}
