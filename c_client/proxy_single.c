#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define MAX_PROXY_CLIENTS 256
#define READ_CHUNK (16 * 1024)
#define BUFFER_SIZE 16384

typedef enum
{
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_CONNECT
} http_method;

typedef enum
{
    TLS_HANDSHAKE_NONE = 0,
    TLS_HANDSHAKE_CLIENT,
    TLS_HANDSHAKE_SERVER,
    TLS_HANDSHAKE_COMPLETE
} tls_handshake_state;

typedef struct
{
    int cli_fd;
    int ser_fd;

    bool is_https;
    bool header_injected;
    SSL *cli_ssl;
    SSL *ser_ssl;
    char hostname[256];
    int port;

    tls_handshake_state handshake_state;
    X509 *fake_cert;
    EVP_PKEY *fake_key;

    char *req_buf;
    size_t req_len;
    size_t req_cap;
    size_t req_sent;

    char *resp_buf;
    size_t resp_len;
    size_t resp_cap;
    size_t resp_got;
    bool resp_headers_complete;
    bool resp_is_chunked;
    bool resp_has_content_length;
    size_t resp_content_length;
    size_t resp_header_len;
    bool resp_complete;
    bool resp_logged_encoding;
    bool resp_filtered_sent;
    bool request_checked;
    bool should_filter;
    bool request_rewritten;

} proxy_client;

static proxy_client *clients[MAX_PROXY_CLIENTS];

static SSL_CTX *server_ctx = NULL;
static SSL_CTX *client_ctx = NULL;
static EVP_PKEY *ca_private_key = NULL;
static X509 *ca_cert = NULL;
static int python_sockfd = -1;
static char py_host[256] = {0};
static int py_port = 0;

static void error(const char *msg)
{
    perror(msg);
    exit(1);
}

static bool match_http_start(const char *buf, size_t len)
{
    if (len == 0 || buf == NULL) {
        return false;
    }
    char *pattern = "HTTP/";

    size_t pat_len = strlen(pattern);
    size_t cmp_len = len < pat_len ? len : pat_len;
    if (strncasecmp(buf, pattern, cmp_len) == 0) {
        return true;
    }

    return false;
}

static bool contains_terminator(const char *buf, size_t len, const char *needle, size_t needle_len)
{
    if (needle_len == 0 || len < needle_len) return false;
    for (size_t i = 0; i + needle_len <= len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) return true;
    }
    return false;
}

static bool is_request_complete(const char *buf, size_t len)
{
    if (len < 4) return false;

    // Find end of headers
    const char *hdr_end = NULL;
    for (size_t i = 0; i + 3 < len; ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            hdr_end = buf + i + 4;
            break;
        }
    }
    
    if (!hdr_end) return false;  // Headers not complete yet
    
    // Check for Content-Length header
    const char *cl = strcasestr(buf, "\r\nContent-Length:");
    if (cl && cl < hdr_end) {
        // Has Content-Length, need to read that many bytes after headers
        size_t content_length = strtoul(cl + 17, NULL, 10);
        size_t header_len = (size_t)(hdr_end - buf);
        size_t body_received = len - header_len;
        return body_received >= content_length;
    }
    
    // Check for Transfer-Encoding: chunked
    const char *te = strcasestr(buf, "\r\nTransfer-Encoding:");
    if (te && te < hdr_end && strcasestr(te, "chunked")) {
        // Chunked encoding - check for final chunk
        return contains_terminator(hdr_end, len - (size_t)(hdr_end - buf), "0\r\n\r\n", 5);
    }
    
    // No body expected (GET request or no Content-Length)
    return true;
}

static char *encode_chunked(const char *body, size_t body_len, size_t *out_len)
{
    // Worst case overhead: each chunk adds ~12 bytes for len+CRLF and final chunk 5 bytes.
    size_t capacity = body_len + (body_len / 8192 + 2) * 16 + 16;
    char *buf = malloc(capacity);
    if (!buf) return NULL;

    size_t written = 0;
    size_t remaining = body_len;
    const char *p = body;
    size_t chunk_size = 8192;

    while (remaining > 0) {
        size_t this_chunk = remaining < chunk_size ? remaining : chunk_size;
        int n = snprintf(buf + written, capacity - written, "%zx\r\n", this_chunk);
        written += (size_t)n;
        memcpy(buf + written, p, this_chunk);
        written += this_chunk;
        buf[written++] = '\r';
        buf[written++] = '\n';
        p += this_chunk;
        remaining -= this_chunk;
    }

    memcpy(buf + written, "0\r\n\r\n", 5);
    written += 5;

    *out_len = written;
    return buf;
}

static bool path_matches_filter(const char *path)
{
    if (!path) return false;
    if (strncasecmp(path, "/youtubei/v1/next", 17) == 0) return true;
    if (strncasecmp(path, "/youtubei/v1/search", 19) == 0) return true;
    if (strncasecmp(path, "/youtubei/v1/browse", 19) == 0) return true;
    return false;
}

static void evaluate_filter_for_request(proxy_client *cli)
{
    if (cli->request_checked) return;
    char *hdr_end = strstr(cli->req_buf, "\r\n\r\n");
    if (!hdr_end) return;

    cli->request_checked = true;
    cli->should_filter = false;

    const char *start = cli->req_buf;
    const char *sp1 = strchr(start, ' ');
    if (!sp1) return;
    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return;

    size_t path_len = (size_t)(sp2 - sp1 - 1);
    if (path_len == 0 || path_len >= 512) return;
    char path[512];
    memcpy(path, sp1 + 1, path_len);
    path[path_len] = '\0';

    const char *host_line = strcasestr(cli->req_buf, "\r\nHost:");
    if (!host_line) return;
    host_line += 7;
    while (*host_line == ' ') host_line++;
    const char *host_end = strstr(host_line, "\r\n");
    if (!host_end) return;
    size_t host_len = (size_t)(host_end - host_line);
    if (host_len == 0 || host_len >= 256) return;
    char host[256];
    memcpy(host, host_line, host_len);
    host[host_len] = '\0';

    // Require youtube host and matching API path
    if (strcasestr(host, "youtube.com") && path_matches_filter(path)) {
        cli->should_filter = true;
        fprintf(stderr, "[filter] request matched filter host=%s path=%s\n", host, path);
    } else {
        fprintf(stderr, "[filter] request not filtered host=%s path=%s\n", host, path);
    }
}

static void close_client(int idx)
{
    proxy_client *cli = clients[idx];
    if (cli == NULL) {
        return;
    }

    if (cli->cli_ssl != NULL) {
        SSL_shutdown(cli->cli_ssl);
        SSL_free(cli->cli_ssl);
    }
    if (cli->ser_ssl != NULL) {
        SSL_shutdown(cli->ser_ssl);
        SSL_free(cli->ser_ssl);
    }

    if (cli->fake_cert != NULL) {
        X509_free(cli->fake_cert);
    }
    if (cli->fake_key != NULL) {
        EVP_PKEY_free(cli->fake_key);
    }

    free(cli->req_buf);
    free(cli->resp_buf);

    if (cli->cli_fd >= 0) {
        close(cli->cli_fd);
    }
    if (cli->ser_fd >= 0) {
        close(cli->ser_fd);
    }

    free(cli);
    clients[idx] = NULL;
}

static int find_free_slot(void)
{
    for (int i = 0; i < MAX_PROXY_CLIENTS; ++i) {
        if (clients[i] == NULL) {
            return i;
        }
    }
    return -1;
}

static void accept_new_client(int server_fd)
{
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        return;
    }

    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl set non-blocking");
        close(client_fd);
        return;
    }

    int slot = find_free_slot();
    if (slot == -1) {
        fprintf(stderr, "Maximum client capacity reached, dropping connection.\n");
        close(client_fd);
        return;
    }

    proxy_client *cli = calloc(1, sizeof(proxy_client));
    if (cli == NULL) {
        perror("calloc");
        close(client_fd);
        return;
    }

    cli->cli_fd = client_fd;
    cli->ser_fd = -1;
    cli->is_https = false;
    cli->header_injected = false;
    cli->handshake_state = TLS_HANDSHAKE_NONE;
    cli->fake_cert = NULL;
    cli->fake_key = NULL;
    cli->cli_ssl = NULL;
    cli->ser_ssl = NULL;
    cli->req_cap = READ_CHUNK * 4;
    cli->req_buf = calloc(1, cli->req_cap + 1);
    cli->resp_cap = READ_CHUNK * 4;
    cli->resp_buf = calloc(1, cli->resp_cap + 1);
    cli->resp_headers_complete = false;
    cli->resp_is_chunked = false;
    cli->resp_has_content_length = false;
    cli->resp_content_length = 0;
    cli->resp_header_len = 0;
    cli->resp_complete = false;
    cli->resp_logged_encoding = false;
    cli->resp_filtered_sent = false;
    cli->request_checked = false;
    cli->should_filter = false;
    cli->request_rewritten = false;

    clients[slot] = cli;
    printf("New client connected (slot %d)\n", slot);
}

static http_method detect_method(const char *buffer)
{
    if (strncmp(buffer, "GET ", 4) == 0) {
        return HTTP_METHOD_GET;
    }
    if (strncmp(buffer, "CONNECT ", 8) == 0) {
        return HTTP_METHOD_CONNECT;
    }
    return HTTP_METHOD_UNKNOWN;
}



static int connect_to_server(const char *hostname, int port)
{
    struct hostent *server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "gethostbyname failed for %s\n", hostname);
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in serv_addr;
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect to server");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int ensure_python_connection(void)
{
    if (python_sockfd >= 0) {
        return python_sockfd;
    }

    python_sockfd = connect_to_server(py_host, py_port);
    if (python_sockfd < 0) {
        fprintf(stderr, "Failed to connect to python filter %s:%d\n", py_host, py_port);
    }
    else {
        // Set modest timeouts so we don't hang forever waiting for the filter
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(python_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(python_sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return python_sockfd;
}

static void close_python_connection(void)
{
    if (python_sockfd >= 0) {
        close(python_sockfd);
        python_sockfd = -1;
    }
}

static int filter_chunked_via_python(const char *body, size_t body_len, char **out_body, size_t *out_len)
{
    int sock = ensure_python_connection();
    if (sock < 0) {
        fprintf(stderr, "[filter] failed to connect to python %s:%d\n", py_host, py_port);
        return -1;
    }

    fprintf(stderr, "[filter] sending %zu bytes to python %s:%d\n", body_len, py_host, py_port);
    size_t written = 0;
    while (written < body_len) {
        ssize_t w = write(sock, body + written, body_len - written);
        if (w < 0) {
            perror("[filter] write to python");
            close_python_connection();
            return -1;
        }
        written += (size_t)w;
    }
    fprintf(stderr, "[filter] wrote %zu bytes to python\n", written);

    size_t cap = body_len > 0 ? body_len * 2 : 8192;
    char *buf = malloc(cap);
    if (!buf) {
        fprintf(stderr, "[filter] malloc failed while reading python response\n");
        return -1;
    }
    size_t len = 0;
    char tmp[BUFFER_SIZE];

    bool saw_terminator = false;
    while (1) {
        ssize_t n = read(sock, tmp, sizeof(tmp));
        if (n <= 0) {
            if (n < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    fprintf(stderr, "[filter] timeout waiting for python response\n");
                } else {
                    perror("[filter] read from python");
                }
            }
            close_python_connection();
            free(buf);
            return -1;
        }
        if (len + (size_t)n > cap) {
            cap = (cap + (size_t)n) * 2;
            char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                return -1;
            }
            buf = nb;
        }
        memcpy(buf + len, tmp, (size_t)n);
        len += (size_t)n;

        if (len >= 5 && contains_terminator(buf, len, "0\r\n\r\n", 5)) {
            saw_terminator = true;
            break;
        }
    }

    *out_body = buf;
    *out_len = len;
    fprintf(stderr, "[filter] received %zu bytes from python%s\n", len, saw_terminator ? " (terminator seen)" : "");
    return 0;
}

static bool parse_http_request(const char *req, char *hostname, int *port)
{
    const char *host_line = strstr(req, "\r\nHost: ");
    if (!host_line) {
        host_line = strstr(req, "\r\nhost: ");
    }
    if (!host_line) {
        return false;
    }

    host_line += 8;
    const char *host_end = strstr(host_line, "\r\n");
    if (!host_end) {
        return false;
    }

    int host_len = host_end - host_line;
    if (host_len >= 255) {
        return false;
    }

    const char *colon = strchr(host_line, ':');
    if (colon && colon < host_end) {
        int hostname_len = colon - host_line;
        strncpy(hostname, host_line, hostname_len);
        hostname[hostname_len] = '\0';
        *port = atoi(colon + 1);
    } else {
        strncpy(hostname, host_line, host_len);
        hostname[host_len] = '\0';
        *port = 80;
    }

    return true;
}

static void handle_http_get(int idx)
{
    proxy_client *cli = clients[idx];

    char hostname[256];
    int port;

    if (!parse_http_request(cli->req_buf, hostname, &port)) {
        fprintf(stderr, "Failed to parse HTTP request\n");
        close_client(idx);
        return;
    }

    printf("HTTP GET to %s:%d\n", hostname, port);

    cli->ser_fd = connect_to_server(hostname, port);
    if (cli->ser_fd < 0) {
        fprintf(stderr, "Failed to connect to %s:%d\n", hostname, port);
        close_client(idx);
        return;
    }

    printf("Connected to %s:%d\n", hostname, port);
}

static int generate_fake_certificate(const char *hostname, X509 **cert_out, EVP_PKEY **key_out)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    X509_NAME *name = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        goto error;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        fprintf(stderr, "Failed to init keygen\n");
        goto error;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        fprintf(stderr, "Failed to set RSA key size\n");
        goto error;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        goto error;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = NULL;

    cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Failed to create X509 certificate\n");
        goto error;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)hostname, -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    char san_value[512];
    snprintf(san_value, sizeof(san_value), "DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san_value);
    if (!ext || !X509_add_ext(cert, ext, -1)) {
        fprintf(stderr, "Failed to add SAN extension\n");
        if (ext) X509_EXTENSION_free(ext);
        goto error;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (!ext || !X509_add_ext(cert, ext, -1)) {
        fprintf(stderr, "Failed to add BasicConstraints extension\n");
        if (ext) X509_EXTENSION_free(ext);
        goto error;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature,keyEncipherment");
    if (!ext || !X509_add_ext(cert, ext, -1)) {
        fprintf(stderr, "Failed to add KeyUsage extension\n");
        if (ext) X509_EXTENSION_free(ext);
        goto error;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth");
    if (!ext || !X509_add_ext(cert, ext, -1)) {
        fprintf(stderr, "Failed to add ExtendedKeyUsage extension\n");
        if (ext) X509_EXTENSION_free(ext);
        goto error;
    }
    X509_EXTENSION_free(ext);

    if (!X509_sign(cert, ca_private_key, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    *cert_out = cert;
    *key_out = pkey;
    return 1;

error:
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    return 0;
}

static void handle_connect(int idx)
{
    proxy_client *cli = clients[idx];

    char *start = cli->req_buf + 8;
    char *colon = strchr(start, ':');
    char *space = strchr(start, ' ');

    if (!colon || !space || colon > space) {
        fprintf(stderr, "Invalid CONNECT request\n");
        close_client(idx);
        return;
    }

    int hostname_len = colon - start;
    if (hostname_len >= 255) {
        fprintf(stderr, "Hostname too long\n");
        close_client(idx);
        return;
    }

    char hostname[256];
    strncpy(hostname, start, hostname_len);
    hostname[hostname_len] = '\0';

    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %d\n", port);
        close_client(idx);
        return;
    }

    printf("CONNECT to %s:%d\n", hostname, port);

    cli->ser_fd = connect_to_server(hostname, port);
    if (cli->ser_fd < 0) {
        fprintf(stderr, "Failed to connect to %s:%d\n", hostname, port);
        close_client(idx);
        return;
    }

    int flags = fcntl(cli->ser_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(cli->ser_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl set server non-blocking");
        close_client(idx);
        return;
    }

    snprintf(cli->hostname, sizeof(hostname), "%s", hostname);
    cli->port = port;
    cli->is_https = true;
    cli->request_checked = false;
    cli->should_filter = false;
    cli->request_rewritten = false;
    cli->req_len = 0;
    cli->req_sent = 0;

    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    ssize_t wrote = write(cli->cli_fd, response, strlen(response));
    if (wrote < 0) {
        perror("write 200 response");
        close_client(idx);
        return;
    }

    printf("Sent 200 Connection Established for %s:%d\n", hostname, port);

    if (!generate_fake_certificate(cli->hostname, &cli->fake_cert, &cli->fake_key)) {
        fprintf(stderr, "Failed to generate certificate for %s\n", cli->hostname);
        close_client(idx);
        return;
    }

    printf("Generated fake certificate for %s\n", cli->hostname);

    cli->handshake_state = TLS_HANDSHAKE_CLIENT;
    cli->req_len = 0;
    cli->req_sent = 0;
}

static SSL_CTX *get_server_ctx(void)
{
    return server_ctx;
}

static SSL_CTX *get_client_ctx(void)
{
    return client_ctx;
}

static void handle_tls_handshake_client(int idx)
{
    proxy_client *cli = clients[idx];

    if (cli->cli_ssl == NULL) {
        cli->cli_ssl = SSL_new(get_server_ctx());
        if (!cli->cli_ssl) {
            fprintf(stderr, "Failed to create client SSL\n");
            ERR_print_errors_fp(stderr);
            close_client(idx);
            return;
        }

        SSL_set_fd(cli->cli_ssl, cli->cli_fd);
        SSL_use_certificate(cli->cli_ssl, cli->fake_cert);
        SSL_use_PrivateKey(cli->cli_ssl, cli->fake_key);
        SSL_set_accept_state(cli->cli_ssl);
    }

    int ret = SSL_accept(cli->cli_ssl);
    if (ret == 1) {
        printf("Client TLS handshake completed for %s\n", cli->hostname);
        cli->handshake_state = TLS_HANDSHAKE_SERVER;
        return;
    }

    int err = SSL_get_error(cli->cli_ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return;
    }

    fprintf(stderr, "SSL_accept failed: %d\n", err);
    ERR_print_errors_fp(stderr);
    close_client(idx);
}

static void handle_tls_handshake_server(int idx)
{
    proxy_client *cli = clients[idx];

    if (cli->ser_ssl == NULL) {
        cli->ser_ssl = SSL_new(get_client_ctx());
        if (!cli->ser_ssl) {
            fprintf(stderr, "Failed to create server SSL\n");
            ERR_print_errors_fp(stderr);
            close_client(idx);
            return;
        }

        SSL_set_fd(cli->ser_ssl, cli->ser_fd);
        SSL_set_tlsext_host_name(cli->ser_ssl, cli->hostname);
        SSL_set_connect_state(cli->ser_ssl);
    }

    int ret = SSL_connect(cli->ser_ssl);
    if (ret == 1) {
        printf("Server TLS handshake completed for %s\n", cli->hostname);
        cli->handshake_state = TLS_HANDSHAKE_COMPLETE;
        return;
    }

    int err = SSL_get_error(cli->ser_ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return;
    }

    fprintf(stderr, "SSL_connect failed: %d\n", err);
    ERR_print_errors_fp(stderr);
    close_client(idx);
}

static void handle_client_initial_request(int idx)
{
    proxy_client *cli = clients[idx];

    ssize_t n = read(cli->cli_fd,
                     cli->req_buf + cli->req_len,
                     BUFFER_SIZE - cli->req_len);

    if (n <= 0) {
        if (n < 0) perror("read from client");
        close_client(idx);
        return;
    }

    cli->req_len += n;
    cli->req_buf[cli->req_len] = '\0';

    if (!is_request_complete(cli->req_buf, cli->req_len)) {
        return;
    }

    http_method method = detect_method(cli->req_buf);

    if (method == HTTP_METHOD_GET) {
        handle_http_get(idx);
    } else if (method == HTTP_METHOD_CONNECT) {
        handle_connect(idx);
    } else {
        fprintf(stderr, "Unsupported method\n");
        close_client(idx);
    }
}

static void read_from_client(int idx)
{
    proxy_client *cli = clients[idx];

    if (cli->req_len >= BUFFER_SIZE) {
        return;
    }

    ssize_t n;
    if (cli->cli_ssl) {
        if (cli->req_cap - cli->req_len < READ_CHUNK) {
            size_t new_cap = cli->req_cap * 2;
            char *nb = realloc(cli->req_buf, new_cap + 1);
            if (!nb) {
                perror("realloc req_buf");
                close_client(idx);
                return;
            }
            cli->req_buf = nb;
            cli->req_cap = new_cap;
        }
        n = SSL_read(cli->cli_ssl,
                     cli->req_buf + cli->req_len,
                     cli->req_cap - cli->req_len);
        if (n <= 0) {
            int err = SSL_get_error(cli->cli_ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return;
            }
            if (n < 0) {
                fprintf(stderr, "SSL_read from client failed\n");
                ERR_print_errors_fp(stderr);
            }
            close_client(idx);
            return;
        }
    } else {
        if (cli->req_cap - cli->req_len < READ_CHUNK) {
            size_t new_cap = cli->req_cap * 2;
            char *nb = realloc(cli->req_buf, new_cap + 1);
            if (!nb) {
                perror("realloc req_buf");
                close_client(idx);
                return;
            }
            cli->req_buf = nb;
            cli->req_cap = new_cap;
        }
        n = read(cli->cli_fd,
                cli->req_buf + cli->req_len,
                cli->req_cap - cli->req_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            perror("read from client");
            close_client(idx);
            return;
        }
        if (n == 0) {
            close_client(idx);
            return;
        }
    }

    cli->req_len += n;
    if (cli->req_len >= cli->req_cap) {
        size_t new_cap = cli->req_cap * 2;
        while (new_cap <= cli->req_len) new_cap *= 2;
        char *nb = realloc(cli->req_buf, new_cap + 1);
        if (!nb) {
            perror("realloc req_buf");
            close_client(idx);
            return;
        }
        cli->req_buf = nb;
        cli->req_cap = new_cap;
    }
    cli->req_buf[cli->req_len] = '\0';
    evaluate_filter_for_request(cli);
}

static void write_to_server(int idx)
{
    proxy_client *cli = clients[idx];

    if (cli->req_sent >= cli->req_len) {
        return;
    }

    size_t to_send = cli->req_len - cli->req_sent;
    ssize_t wrote;

    if (cli->ser_ssl) {
        wrote = SSL_write(cli->ser_ssl,
                         cli->req_buf + cli->req_sent,
                         to_send);
        if (wrote <= 0) {
            int err = SSL_get_error(cli->ser_ssl, wrote);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return;
            }
            fprintf(stderr, "SSL_write to server failed\n");
            ERR_print_errors_fp(stderr);
            close_client(idx);
            return;
        }
    } else {
        wrote = write(cli->ser_fd,
                     cli->req_buf + cli->req_sent,
                     to_send);
        if (wrote < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return;
            }
            perror("write to server");
            close_client(idx);
            return;
        }
    }

    cli->req_sent += wrote;

    if (cli->req_sent == cli->req_len) {
        cli->req_len = 0;
        cli->req_sent = 0;
    }
}

static void read_from_server(int idx)
{
    proxy_client *cli = clients[idx];

    if (cli->resp_complete) {
        return;
    }

    if (cli->resp_cap - cli->resp_len < READ_CHUNK) {
        size_t new_cap = cli->resp_cap * 2;
        char *nb = realloc(cli->resp_buf, new_cap + 1);
        if (!nb) {
            perror("realloc resp_buf");
            close_client(idx);
            return;
        }
        cli->resp_buf = nb;
        cli->resp_cap = new_cap;
    }

    bool buffer_was_empty = (cli->resp_len == 0 && cli->resp_got == 0);

    ssize_t n;
    if (cli->ser_ssl) {
        n = SSL_read(cli->ser_ssl,
                     cli->resp_buf + cli->resp_len,
                     cli->resp_cap - cli->resp_len);
        if (n <= 0) {
            int err = SSL_get_error(cli->ser_ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return;
            }
            if (n < 0) {
                fprintf(stderr, "SSL_read from server failed\n");
                ERR_print_errors_fp(stderr);
            }
            close_client(idx);
            return;
        }
    } else {
        n = read(cli->ser_fd,
                cli->resp_buf + cli->resp_len,
                cli->resp_cap - cli->resp_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            perror("read from server");
            close_client(idx);
            return;
        }
        if (n == 0) {
            close_client(idx);
            return;
        }
    }

    cli->resp_len += n;
    cli->resp_buf[cli->resp_len] = '\0';

    if (!cli->resp_headers_complete) {
        char *hdr_end = strstr(cli->resp_buf, "\r\n\r\n");
        if (hdr_end) {
            cli->resp_headers_complete = true;
            cli->resp_header_len = (hdr_end - cli->resp_buf) + 4;
            if (strcasestr(cli->resp_buf, "Transfer-Encoding: chunked")) {
                cli->resp_is_chunked = true;
                cli->resp_has_content_length = false;
            }
            char *cl = strcasestr(cli->resp_buf, "Content-Length:");
            if (cl && cl < cli->resp_buf + cli->resp_header_len) {
                cli->resp_has_content_length = true;
                cli->resp_content_length = strtoul(cl + 15, NULL, 10);
            } else if (!cli->resp_is_chunked) {
                cli->resp_has_content_length = false;
                cli->resp_content_length = 0;
            }
            if (!cli->resp_logged_encoding) {
                char *ce = strcasestr(cli->resp_buf, "Content-Encoding:");
                if (ce && ce < cli->resp_buf + cli->resp_header_len) {
                    char *line_end = strstr(ce, "\r\n");
                    size_t line_len = line_end ? (size_t)(line_end - ce) : 0;
                    fprintf(stderr, "[resp] Content-Encoding detected: %.*s\n", (int)line_len, ce);
                } else {
                    fprintf(stderr, "[resp] Content-Encoding: none\n");
                }
                cli->resp_logged_encoding = true;
            }
        }
    }

    if (cli->resp_is_chunked && cli->resp_headers_complete) {
        if (cli->resp_len >= cli->resp_header_len &&
            contains_terminator(cli->resp_buf + cli->resp_header_len,
                                cli->resp_len - cli->resp_header_len,
                                "0\r\n\r\n", 5)) {
            cli->resp_complete = true;
            fprintf(stderr, "[resp] chunked complete len=%zu header=%zu\n", cli->resp_len, cli->resp_header_len);
        } else {
            // Debug: show last 20 bytes of response to see what we're waiting for
            size_t body_len = cli->resp_len - cli->resp_header_len;
            if (body_len > 20) {
                fprintf(stderr, "[resp] chunked not complete, last 20 bytes: ");
                for (size_t i = cli->resp_len - 20; i < cli->resp_len; i++) {
                    unsigned char c = (unsigned char)cli->resp_buf[i];
                    if (c >= 32 && c < 127) {
                        fprintf(stderr, "%c", c);
                    } else {
                        fprintf(stderr, "\\x%02x", c);
                    }
                }
                fprintf(stderr, "\n");
            }
        }
    } else if (cli->resp_has_content_length && cli->resp_headers_complete) {
        size_t have_body = (cli->resp_len > cli->resp_header_len) ? cli->resp_len - cli->resp_header_len : 0;
        if (have_body >= cli->resp_content_length) {
            cli->resp_complete = true;
            fprintf(stderr, "[resp] content-length complete len=%zu body=%zu\n", cli->resp_len, have_body);
        }
    }

    if (buffer_was_empty && match_http_start(cli->resp_buf, cli->resp_len)) {
        cli->header_injected = false;
        cli->resp_headers_complete = false;
        cli->resp_is_chunked = false;
        cli->resp_has_content_length = false;
        cli->resp_content_length = 0;
        cli->resp_header_len = 0;
        cli->resp_complete = false;
        cli->resp_logged_encoding = false;
        cli->resp_filtered_sent = false;
    }
}

static void write_to_client(int idx)
{
    proxy_client *cli = clients[idx];

    // If this response needs filtering, wait until it is fully buffered before sending anything.
    if (cli->should_filter &&
        (cli->resp_is_chunked || cli->resp_has_content_length) &&
        !cli->resp_complete) {
        return;
    }

    if (cli->should_filter && (cli->resp_is_chunked || cli->resp_has_content_length) && cli->resp_complete && !cli->resp_filtered_sent) {
        fprintf(stderr, "[filter] start filtering response len=%zu (header %zu)\n", cli->resp_len, cli->resp_header_len);
        const char *body = cli->resp_buf + cli->resp_header_len;
        size_t body_len = cli->resp_len - cli->resp_header_len;
        char *chunked_body = NULL;
        size_t chunked_len = 0;

        if (cli->resp_is_chunked) {
            chunked_body = (char *)body;
            chunked_len = body_len;
        } else {
            chunked_body = encode_chunked(body, body_len, &chunked_len);
            if (!chunked_body) {
                return;
            }
        }

        char *filtered = NULL;
        size_t filtered_len = 0;

        if (filter_chunked_via_python(chunked_body, chunked_len, &filtered, &filtered_len) == 0) {
            // rebuild header: remove Content-Length, ensure Transfer-Encoding: chunked
            size_t header_out_cap = cli->resp_header_len + 256;
            char *header_out = malloc(header_out_cap);
            size_t header_out_len = 0;
            if (header_out) {
                const char *p = cli->resp_buf;
                const char *end = cli->resp_buf + cli->resp_header_len;
                while (p < end) {
                    const char *line_end = strstr(p, "\r\n");
                    if (!line_end) break;
                    size_t line_len = (size_t)(line_end - p) + 2;
                    // Stop at the blank line
                    if (line_len == 2) {
                        break;
                    }
                    if (strncasecmp(p, "Content-Length:", 15) == 0) {
                        // skip
                    } else if (strncasecmp(p, "Transfer-Encoding:", 18) == 0) {
                        // skip existing TE and add our own later
                    } else {
                        if (header_out_len + line_len + 64 > header_out_cap) {
                            header_out_cap *= 2;
                            char *nb = realloc(header_out, header_out_cap);
                            if (!nb) break;
                            header_out = nb;
                        }
                        memcpy(header_out + header_out_len, p, line_len);
                        header_out_len += line_len;
                    }
                    p = line_end + 2;
                    if (p >= end) break;
                }
                const char *te = "Transfer-Encoding: chunked\r\n\r\n";
                size_t te_len = strlen(te);
                if (header_out_len + te_len > header_out_cap) {
                    header_out_cap = header_out_len + te_len + 32;
                    char *nb = realloc(header_out, header_out_cap);
                    if (nb) header_out = nb;
                }
                memcpy(header_out + header_out_len, te, te_len);
                header_out_len += te_len;
                fprintf(stderr, "[filter] sending header (%zu bytes):\n%.*s\n", header_out_len, (int)header_out_len, header_out);
            }

            const char *hdr_ptr = header_out ? header_out : cli->resp_buf;
            size_t hdr_len = header_out ? header_out_len : cli->resp_header_len;

            size_t header_written = 0;
            while (header_written < hdr_len) {
                ssize_t w;
                if (cli->cli_ssl) {
                    w = SSL_write(cli->cli_ssl, hdr_ptr + header_written, hdr_len - header_written);
                    if (w <= 0) {
                        int err = SSL_get_error(cli->cli_ssl, w);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            continue;  // Retry
                        }
                        fprintf(stderr, "[filter] SSL_write header failed\n");
                        break;
                    }
                } else {
                    w = write(cli->cli_fd, hdr_ptr + header_written, hdr_len - header_written);
                    if (w < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            continue;  // Retry
                        }
                        perror("[filter] write header failed");
                        break;
                    }
                }
                header_written += (size_t)w;
            }
            fprintf(stderr, "[filter] header sent: %zu/%zu bytes\n", header_written, hdr_len);

            size_t body_written = 0;
            while (body_written < filtered_len) {
                ssize_t w;
                if (cli->cli_ssl) {
                    w = SSL_write(cli->cli_ssl, filtered + body_written, filtered_len - body_written);
                    if (w <= 0) {
                        int err = SSL_get_error(cli->cli_ssl, w);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            continue;  // Retry
                        }
                        fprintf(stderr, "[filter] SSL_write body failed\n");
                        break;
                    }
                } else {
                    w = write(cli->cli_fd, filtered + body_written, filtered_len - body_written);
                    if (w < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            continue;  // Retry
                        }
                        perror("[filter] write body failed");
                        break;
                    }
                }
                body_written += (size_t)w;
            }
            fprintf(stderr, "[filter] body sent: %zu/%zu bytes\n", body_written, filtered_len);

            free(header_out);
        } else {
            fprintf(stderr, "filter_chunked_via_python failed, sending original response\n");
            cli->should_filter = false; // avoid repeated attempts if python side is down
            // fall back to sending original
            size_t sent = 0;
            while (sent < cli->resp_len) {
                ssize_t w = cli->cli_ssl
                                ? SSL_write(cli->cli_ssl, cli->resp_buf + sent, cli->resp_len - sent)
                                : write(cli->cli_fd, cli->resp_buf + sent, cli->resp_len - sent);
                if (w <= 0) break;
                sent += (size_t)w;
            }
        }

        if (!cli->resp_is_chunked && chunked_body && chunked_body != body) {
            free(chunked_body);
        }
        free(filtered);
        // Reset all response state for next request on this connection
        cli->resp_filtered_sent = true;
        cli->resp_len = 0;
        cli->resp_got = 0;
        cli->resp_complete = false;
        cli->resp_headers_complete = false;
        cli->resp_header_len = 0;
        cli->resp_is_chunked = false;
        cli->resp_has_content_length = false;
        cli->resp_content_length = 0;
        cli->resp_logged_encoding = false;
        cli->should_filter = false;
        cli->request_checked = false;
        cli->request_rewritten = false;
        cli->header_injected = false;
        return;
    }

    if (cli->resp_got >= cli->resp_len) {
        return;
    }

    if (!cli->header_injected) {
        // Check if this looks like an HTTP response
        if (!match_http_start(cli->resp_buf, cli->resp_len)) {
            // Not an HTTP response, just forward as-is without header injection
            cli->header_injected = true;  // Mark as "done" so we don't keep checking
            cli->resp_got = 0;  // Start from beginning
        } else {
            char *first_line_end = strstr(cli->resp_buf, "\r\n");
            if (!first_line_end) {
                return;  // Wait for more data
            }

            size_t first_line_len = first_line_end - cli->resp_buf + 2;

            ssize_t wrote;
            if (cli->cli_ssl) {
                wrote = SSL_write(cli->cli_ssl, cli->resp_buf, first_line_len);
                if (wrote <= 0) {
                    int err = SSL_get_error(cli->cli_ssl, wrote);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        return;
                    }
                    fprintf(stderr, "SSL_write to client failed\n");
                    ERR_print_errors_fp(stderr);
                    close_client(idx);
                    return;
                }
            } else {
                wrote = write(cli->cli_fd, cli->resp_buf, first_line_len);
                if (wrote < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        return;
                    }
                    perror("write to client");
                    close_client(idx);
                    return;
                }
            }

            const char *inject = "X-Proxy:CS112\r\n";
            if (cli->cli_ssl) {
                wrote = SSL_write(cli->cli_ssl, inject, strlen(inject));
                if (wrote <= 0) {
                    int err = SSL_get_error(cli->cli_ssl, wrote);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        return;
                    }
                    fprintf(stderr, "SSL_write inject header failed\n");
                    ERR_print_errors_fp(stderr);
                    close_client(idx);
                    return;
                }
            } else {
                wrote = write(cli->cli_fd, inject, strlen(inject));
                if (wrote < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        return;
                    }
                    perror("write inject header");
                    close_client(idx);
                    return;
                }
            }

            cli->header_injected = true;
            cli->resp_got = first_line_len;
        }
    }

    if (cli->resp_got < cli->resp_len) {
        size_t to_send = cli->resp_len - cli->resp_got;
        ssize_t wrote;

        if (cli->cli_ssl) {
            wrote = SSL_write(cli->cli_ssl,
                            cli->resp_buf + cli->resp_got,
                            to_send);
            if (wrote <= 0) {
                int err = SSL_get_error(cli->cli_ssl, wrote);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    return;
                }
                fprintf(stderr, "SSL_write to client failed err=%d\n", err);
                ERR_print_errors_fp(stderr);
                close_client(idx);
                return;
            }
        } else {
            wrote = write(cli->cli_fd,
                         cli->resp_buf + cli->resp_got,
                         to_send);
            if (wrote < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    return;
                }
                perror("write to client");
                close_client(idx);
                return;
            }
        }

        cli->resp_got += wrote;
    }

    if (cli->resp_got == cli->resp_len) {
        // Reset all response state for next request on this connection
        cli->resp_len = 0;
        cli->resp_got = 0;
        cli->should_filter = false;
        cli->request_checked = false;
        cli->request_rewritten = false;
        cli->header_injected = false;
        cli->resp_headers_complete = false;
        cli->resp_is_chunked = false;
        cli->resp_has_content_length = false;
        cli->resp_content_length = 0;
        cli->resp_header_len = 0;
        cli->resp_complete = false;
        cli->resp_logged_encoding = false;
    }
}

static void run_client_loop(int server_fd)
{
    memset(clients, 0, sizeof(clients));

    printf("Proxy server running...\n");

    while (1) {
        fd_set readfds, writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        FD_SET(server_fd, &readfds);
        int max_fd = server_fd;

        for (int i = 0; i < MAX_PROXY_CLIENTS; i++) {
            proxy_client *cli = clients[i];
            if (cli == NULL) continue;

            if (cli->handshake_state == TLS_HANDSHAKE_CLIENT) {
                FD_SET(cli->cli_fd, &readfds);
                FD_SET(cli->cli_fd, &writefds);
                if (cli->cli_fd > max_fd) max_fd = cli->cli_fd;
                continue;
            } else if (cli->handshake_state == TLS_HANDSHAKE_SERVER) {
                FD_SET(cli->ser_fd, &readfds);
                FD_SET(cli->ser_fd, &writefds);
                if (cli->ser_fd > max_fd) max_fd = cli->ser_fd;
                continue;
            }

            if (cli->cli_fd >= 0) {
                FD_SET(cli->cli_fd, &readfds);
                if (cli->cli_fd > max_fd) max_fd = cli->cli_fd;
            }

            if (cli->ser_fd >= 0) {
                FD_SET(cli->ser_fd, &readfds);
                if (cli->ser_fd > max_fd) max_fd = cli->ser_fd;
            }

            if (cli->ser_fd >= 0 && cli->req_sent < cli->req_len) {
                FD_SET(cli->ser_fd, &writefds);
            }

            // Only add client fd to writefds if we have something to write
            // For filtered responses, wait until response is complete
            if (cli->cli_fd >= 0 && cli->resp_got < cli->resp_len) {
                if (cli->should_filter && !cli->resp_complete) {
                    // Waiting for full response before filtering, don't trigger write yet
                } else {
                    FD_SET(cli->cli_fd, &writefds);
                }
            }
        }

        int ready = select(max_fd + 1, &readfds, &writefds, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            accept_new_client(server_fd);
        }

        for (int i = 0; i < MAX_PROXY_CLIENTS; i++) {
            proxy_client *cli = clients[i];
            if (cli == NULL) continue;

            if (cli->handshake_state == TLS_HANDSHAKE_CLIENT) {
                if (FD_ISSET(cli->cli_fd, &readfds) ||
                    FD_ISSET(cli->cli_fd, &writefds)) {
                    handle_tls_handshake_client(i);
                }
                continue;
            } else if (cli->handshake_state == TLS_HANDSHAKE_SERVER) {
                if (FD_ISSET(cli->ser_fd, &readfds) ||
                    FD_ISSET(cli->ser_fd, &writefds)) {
                    handle_tls_handshake_server(i);
                }
                continue;
            }

            if (FD_ISSET(cli->cli_fd, &readfds)) {
                if (cli->ser_fd < 0) {
                    handle_client_initial_request(i);
                } else {
                    read_from_client(i);
                }
            }
            cli = clients[i];
            if (cli == NULL) continue;

            if (cli->ser_fd >= 0 && FD_ISSET(cli->ser_fd, &readfds)) {
                read_from_server(i);
                cli = clients[i];
                if (cli == NULL) continue;
            }

            if (cli->ser_fd >= 0 && FD_ISSET(cli->ser_fd, &writefds)) {
                write_to_server(i);
                cli = clients[i];
                if (cli == NULL) continue;
            }

            if (cli->cli_fd >= 0 && FD_ISSET(cli->cli_fd, &writefds)) {
                write_to_client(i);
                cli = clients[i];
                if (cli == NULL) continue;
            }
        }
    }

    for (int i = 0; i < MAX_PROXY_CLIENTS; i++) {
        close_client(i);
    }
}

static void init_ssl(const char *ca_cert_path, const char *ca_key_path)
{
    server_ctx = SSL_CTX_new(TLS_server_method());
    if (!server_ctx) {
        fprintf(stderr, "Failed to create server SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    client_ctx = SSL_CTX_new(TLS_client_method());
    if (!client_ctx) {
        fprintf(stderr, "Failed to create client SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    FILE *ca_cert_file = fopen(ca_cert_path, "r");
    if (!ca_cert_file) {
        perror("Cannot open CA certificate");
        exit(1);
    }
    ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);

    if (!ca_cert) {
        fprintf(stderr, "Failed to read CA certificate\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    FILE *ca_key_file = fopen(ca_key_path, "r");
    if (!ca_key_file) {
        perror("Cannot open CA private key");
        exit(1);
    }
    ca_private_key = PEM_read_PrivateKey(ca_key_file, NULL, NULL, NULL);
    fclose(ca_key_file);

    if (!ca_private_key) {
        fprintf(stderr, "Failed to read CA private key\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);

    printf("SSL initialized successfully\n");
}

static void init_python_target(void)
{
    const char *host_env = getenv("PY_SERVER_HOST");
    const char *port_env = getenv("PY_SERVER_PORT");
    if (host_env && strlen(host_env) < sizeof(py_host)) {
        strcpy(py_host, host_env);
    } else {
        strcpy(py_host, "localhost");
    }
    if (port_env) {
        py_port = atoi(port_env);
    }
    if (py_port <= 0) {
        py_port = 5000;
    }
    fprintf(stderr, "Python filter target %s:%d\n", py_host, py_port);
}

int main(int argc, char *argv[])
{
    // Ensure proxy logs flush line-by-line so container logs reflect events before any crash.
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    if (argc < 4)
    {
        error("usage: ./proxy <port> <ca_cert_path> <ca_key_path>");
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);
    int portno = strtol(argv[1], NULL, 10);

    init_ssl(argv[2], argv[3]);
    init_python_target();
    int take_sockfd;
    struct sockaddr_in serv_addr;

    take_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (take_sockfd < 0)
    {
        error("ERROR opening socket");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(take_sockfd, (struct sockaddr *)&serv_addr,
             sizeof(serv_addr)) < 0)
    {
        error("ERROR on binding");
    }
    if (listen(take_sockfd, 128) < 0)
    {
        error("ERROR on listen");
    }
    printf("Socket bound\n");

    run_client_loop(take_sockfd);
    close(take_sockfd);
    return 0;
}
