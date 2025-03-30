#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <pbc/pbc.h>
#include "logger.h"
#include "timer.h"

#define BUFFER_SIZE      8192
#define SHARED_KEY_SIZE  32
#define DIGEST_SIZE      32
#define ID_LEN           16

/*
 * Macros for repeated code patterns
 */
#define CHECK_ALLOC(ptr)                                      \
    do {                                                      \
        if (!(ptr)) {                                         \
            perror("malloc");                                 \
            exit(EXIT_FAILURE);                               \
        }                                                     \
    } while(0)

#define SAFE_STRDUP(dst, src)                                 \
    do {                                                      \
        dst = strdup(src);                                    \
        if (!(dst)) {                                         \
            perror("strdup");                                 \
            exit(EXIT_FAILURE);                               \
        }                                                     \
    } while(0)

#define SNPRINT_AND_APPEND(dst, elem)                         \
    do {                                                      \
        char temp[1024];                                      \
        element_snprint(temp, sizeof(temp), elem);            \
        strcat(dst, temp);                                    \
        strcat(dst, "||");                                    \
    } while(0)

#define SET_ELEM_FROM_TOKEN(elem)                             \
    do {                                                      \
        if (token != NULL) {                                  \
            element_set_str(elem, token, 10);                 \
            token = strtok(NULL, "|");                        \
        }                                                     \
    } while(0)

element_t g1, h1;
element_t Sign_public_key, Sign_secret_key;
element_t sig_Fix;
element_t temp1, temp2;
element_t g2, h2;
element_t San_public_key, San_secret_key;
element_t sig_FULL;
element_t temp3, temp4;
pairing_t pairing;

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void init_openssl_library(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

static SSL_CTX *create_context_server(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context (server)\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

static SSL_CTX *create_context_client(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context (client)\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

static int create_listen_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket() failed");
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("bind() failed");
    if (listen(sockfd, 5) < 0)
        die("listen() failed");
    return sockfd;
}

static int create_client_socket(const char *host, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket() failed");

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);
    inet_pton(AF_INET, host, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        die("connect() failed");

    return sockfd;
}

static void write_u32(unsigned char *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >>  8) & 0xFF;
    buf[3] = (val      ) & 0xFF;
}

static uint32_t read_u32(const unsigned char *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] <<  8) |
           ((uint32_t)buf[3]);
}

static int send_payload(SSL *ssl,
                        const unsigned char *message, size_t msg_len,
                        const unsigned char *ml, size_t ml_len) {
    unsigned char header[8];
    write_u32(header, (uint32_t)msg_len);
    write_u32(header + 4, (uint32_t)ml_len);

    int r = SSL_write(ssl, header, 8);
    if (r != 8) {
        fprintf(stderr, "send_payload: failed to write header\n");
        return -1;
    }

    int total_to_write = (int)(msg_len + ml_len);
    unsigned char *buf = (unsigned char*)malloc(total_to_write);
    CHECK_ALLOC(buf);

    memcpy(buf, message, msg_len);
    memcpy(buf + msg_len, ml, ml_len);

    r = SSL_write(ssl, buf, total_to_write);
    free(buf);

    if (r != total_to_write) {
        fprintf(stderr, "send_payload: failed to write message+ML\n");
        return -1;
    }
    return 0;
}

static int recv_payload(SSL *ssl,
                        unsigned char *message, size_t *msg_len,
                        unsigned char *ml, size_t *ml_len) {
    unsigned char header[8];
    int r = SSL_read(ssl, header, 8);
    if (r <= 0) {
        fprintf(stderr, "recv_payload: failed to read header\n");
        return -1;
    }
    if (r < 8) {
        fprintf(stderr, "recv_payload: partial header?\n");
        return -1;
    }
    uint32_t mlen = read_u32(header);
    uint32_t llen = read_u32(header + 4);
    if (mlen > BUFFER_SIZE || llen > BUFFER_SIZE) {
        fprintf(stderr, "recv_payload: lengths too large?\n");
        return -1;
    }

    unsigned int to_read = mlen + llen;
    unsigned char *tmp = (unsigned char*)malloc(to_read);
    CHECK_ALLOC(tmp);

    r = SSL_read(ssl, tmp, to_read);
    if (r < (int)to_read) {
        fprintf(stderr, "recv_payload: partial read? got %d, needed %u\n", r, to_read);
        free(tmp);
        return -1;
    }
    printf("\nRecieved Modification Log size %u", llen);
    log_printf("\nRecieved Modification Log size %u", llen);

    memcpy(message, tmp, mlen);
    *msg_len = mlen;
    memcpy(ml, tmp + mlen, llen);
    *ml_len = llen;

    free(tmp);
    return 0;
}

static void compute_sha256(const unsigned char *data, size_t data_len,
                           unsigned char out_digest[DIGEST_SIZE]) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    EVP_DigestFinal_ex(mdctx, out_digest, NULL);
    EVP_MD_CTX_free(mdctx);
}

static int generate_signature(const unsigned char* msg, size_t len,
                              unsigned char* sig, size_t sig_size) {
    int size = 0;
    element_from_hash(h1, msg, len);
    element_pow_zn(sig_Fix, h1, Sign_secret_key);
    pairing_apply(temp1, sig_Fix, g1, pairing);

    char temp_buf[1024];
    element_snprint(temp_buf, 1024, h1);
    strcat(sig, temp_buf);
    strcat(sig, "||");
    size += (int)(strlen(temp_buf) + 2);

    element_snprint(temp_buf, 1024, temp1);
    strcat(sig, temp_buf);
    strcat(sig, "||");
    size += (int)(strlen(temp_buf) + 2);

    int size_of_sig = element_length_in_bytes(h1) + element_length_in_bytes(temp1);
    log_printf("Size of signature: %d\n", size_of_sig);
    return size;
}

static int verify_sig(element_t temp2, element_t h1, element_t Sign_public_key, pairing_t pairing) {
    pairing_apply(temp2, h1, Sign_public_key, pairing);
    if (!element_cmp(temp1, temp2)) {
        fprintf(stderr,"m1 signature verifies\n");
        return 0;
    } else {
        fprintf(stderr, "m1 signature does not verify\n");
        return 1;
    }
}

static int generate_sanitizable_signature(const unsigned char* msg, size_t len,
                                          unsigned char* sig, size_t sig_size) {
    int size = 0;
    element_from_hash(h2, msg, strlen(msg));
    element_pow_zn(sig_FULL, h2, San_secret_key);
    pairing_apply(temp3, sig_FULL, g2, pairing);

    char temp_buf[1024];
    element_snprint(temp_buf, 1024, h2);
    strcat(sig, temp_buf);
    strcat(sig, "||");
    size += (int)(strlen(temp_buf) + 2);

    element_snprint(temp_buf, 1024, temp3);
    strcat(sig, temp_buf);
    strcat(sig, "||");
    size += (int)(strlen(temp_buf) + 2);

    int size_of_sig = element_length_in_bytes(h2) + element_length_in_bytes(temp3);
    log_printf("Size of  Sanitized signature: %d\n", size_of_sig);
    return size;
}

static int verify_sanitizable_signature() {
    pairing_apply(temp4, h2, San_public_key, pairing);
    if (!element_cmp(temp3, temp4)) {
        log_printf("FULL signature verifies\n");
        return 0;
    } else {
        log_printf("FULL signature does not verify\n");
        return 1;
    }
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    log_printf("%s [len=%zu]: ", label, len);
    for (size_t i=0; i<len; i++) {
        log_printf("%02X", buf[i]);
    }
    log_printf("\n");
}

static int append_tag(const char *tag,
                      const unsigned char *in_msg, size_t in_len,
                      unsigned char *out_msg, size_t *out_len) {
    size_t tag_len = strlen(tag);
    if (in_len + tag_len > *out_len) {
        fprintf(stderr, "append_tag: buffer too small\n");
        return -1;
    }
    memcpy(out_msg, in_msg, in_len);
    memcpy(out_msg + in_len, tag, tag_len);
    *out_len = in_len + tag_len;
    return 0;
}

static void print_keys() {
    char *result = (char *)malloc(8192);
    CHECK_ALLOC(result);
    result[0] = '\0';

    SNPRINT_AND_APPEND(result, g1);
    SNPRINT_AND_APPEND(result, h1);
    SNPRINT_AND_APPEND(result, Sign_public_key);
    SNPRINT_AND_APPEND(result, Sign_secret_key);
    SNPRINT_AND_APPEND(result, sig_Fix);
    SNPRINT_AND_APPEND(result, temp1);
    SNPRINT_AND_APPEND(result, temp2);
    SNPRINT_AND_APPEND(result, g2);
    SNPRINT_AND_APPEND(result, h2);
    SNPRINT_AND_APPEND(result, San_public_key);
    SNPRINT_AND_APPEND(result, San_secret_key);
    SNPRINT_AND_APPEND(result, sig_FULL);
    SNPRINT_AND_APPEND(result, temp3);
    // For the last one, we won't add "||" so it doesn't appear trailing in logs:
    {
        char temp[1024];
        element_snprint(temp, sizeof(temp), temp4);
        strcat(result, temp);
    }

    /* ... Do whatever you want with 'result' (e.g., log it) ... */
    // log_printf("All keys/elems: %s\n", result); // Example usage
    free(result);
}

static void parse_keys(const char* buf, int buf_len) {
    char *copy;
    SAFE_STRDUP(copy, buf);

    char *token = strtok(copy, "|");
    SET_ELEM_FROM_TOKEN(g1);
    SET_ELEM_FROM_TOKEN(h1);
    SET_ELEM_FROM_TOKEN(Sign_public_key);
    SET_ELEM_FROM_TOKEN(Sign_secret_key);
    SET_ELEM_FROM_TOKEN(sig_Fix);
    SET_ELEM_FROM_TOKEN(temp1);
    SET_ELEM_FROM_TOKEN(temp2);
    SET_ELEM_FROM_TOKEN(g2);
    SET_ELEM_FROM_TOKEN(h2);
    SET_ELEM_FROM_TOKEN(San_public_key);
    SET_ELEM_FROM_TOKEN(San_secret_key);
    SET_ELEM_FROM_TOKEN(sig_FULL);
    SET_ELEM_FROM_TOKEN(temp3);
    SET_ELEM_FROM_TOKEN(temp4);

    print_keys();
    free(copy);
}

static void run_server(int listen_port, const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = create_context_server(cert_file, key_file);
    int server_sock = create_listen_socket(listen_port);
    log_printf("[Server] Listening on port %d...\n", listen_port);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int mb_fd = accept(server_sock, (struct sockaddr*)&addr, &addr_len);
    if (mb_fd < 0) die("accept() failed");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, mb_fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(mb_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_sock);
        return;
    }
    log_printf("[Server] TLS handshake completed with Middlebox.\n");

    char buf[4096];
    memset(buf, 0, sizeof(buf));
    int bytes_c = SSL_read(ssl, buf, sizeof(buf));
    parse_keys(buf, bytes_c);
    if (bytes_c == 0) {
        fprintf(stderr, "[Server] Failed to read the 32-byte shared key.\n");
        goto cleanup;
    }
    log_printf("[Server] Received the 32-byte shared key.\n");

    unsigned char msg_buf[BUFFER_SIZE], ml_buf[BUFFER_SIZE];
    size_t msg_len=0, ml_len=0;
    if (recv_payload(ssl, msg_buf, &msg_len, ml_buf, &ml_len) < 0) {
        fprintf(stderr, "[Server] Error receiving round-trip #2 request.\n");
        goto cleanup;
    }
    {
        char *copy1;
        SAFE_STRDUP(copy1, (char*)ml_buf);
        char *token = strtok(copy1, "|");
        if (token != NULL) { 
            element_set_str(h2, token, 10);
            token = strtok(NULL, "|");
        }
        if (token != NULL) { 
            element_set_str(temp3, token, 10);
            token = strtok(NULL, "|");
        }
        int size1 = element_length_in_bytes(h2);
        int size2 = element_length_in_bytes(temp3);
        printf("Size1 = %d, Size2 = %d\n", size1, size2);
        log_printf("Size1 = %d, Size2 = %d\n", size1, size2);
        pairing_apply(temp4, h2, San_public_key, pairing);
        if (!element_cmp(temp3, temp4)) {
            log_printf("FULL signature verifies\n");
        } else {
            log_printf("FULL signature does not verify\n");
        }
        free(copy1);
    }
    unsigned char server_out[BUFFER_SIZE];
    size_t server_out_len = sizeof(server_out);
    if (append_tag(" [updated_by_Server]", msg_buf, msg_len, server_out, &server_out_len) < 0) {
        fprintf(stderr, "[Server] Could not append server tag.\n");
        goto cleanup;
    }

    unsigned char sig[8192] = {0};
    int sig_len = generate_signature(server_out, server_out_len, sig, sizeof(sig));
    if (send_payload(ssl, server_out, server_out_len, sig, sig_len) < 0) {
        fprintf(stderr, "[Server] send_payload error.\n");
        goto cleanup;
    }
    log_printf("[Server] Sent response (message+ML) to MB.\n");

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(mb_fd);
    close(server_sock);
    SSL_CTX_free(ctx);
    log_printf("[Server] Done.\n");
}

static void run_middlebox(int listen_port,
                          const char *server_host, int server_port,
                          const char *cert_file, const char *key_file) {
    SSL_CTX *ctx_up = create_context_client();
    int up_fd = create_client_socket(server_host, server_port);
    SSL *ssl_up = SSL_new(ctx_up);
    SSL_set_fd(ssl_up, up_fd);

    if (SSL_connect(ssl_up) <= 0) {
        fprintf(stderr, "[MB] SSL_connect to server failed.\n");
        ERR_print_errors_fp(stderr);
        goto mb_fail;
    }
    log_printf("[MB] Connected + TLS handshake with upstream server done.\n");

    SSL_CTX *ctx_down = create_context_server(cert_file, key_file);
    int listen_fd = create_listen_socket(listen_port);
    log_printf("[MB] Listening on port %d for a client...\n", listen_port);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd = accept(listen_fd, (struct sockaddr*)&addr, &addr_len);
    if (client_fd < 0) die("[MB] accept() failed");

    SSL *ssl_down = SSL_new(ctx_down);
    SSL_set_fd(ssl_down, client_fd);
    if (SSL_accept(ssl_down) <= 0) {
        fprintf(stderr, "[MB] SSL_accept from client failed.\n");
        ERR_print_errors_fp(stderr);
        goto mb_cleanup;
    }
    log_printf("[MB] TLS handshake completed with client.\n");

    unsigned char shared_key[SHARED_KEY_SIZE];
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    int bytes_c = SSL_read(ssl_down, buf, sizeof(buf));
    parse_keys(buf, bytes_c);
    if (bytes_c == 0) {
        fprintf(stderr, "[MB] Did not receive 32-byte key from client.\n");
        goto mb_cleanup;
    }
    log_printf("[MB] Received 32-byte key from Client.\n");

    int r = SSL_write(ssl_up, buf, bytes_c);
    if (r != bytes_c) {
        fprintf(stderr, "[MB] Failed to forward 32-byte key to server.\n");
        goto mb_cleanup;
    }
    log_printf("[MB] Forwarded 32-byte key to Server.\n");

    {
        unsigned char msg_buf[BUFFER_SIZE], ml_buf[BUFFER_SIZE];
        size_t msg_len=0, ml_len=0;
        if (recv_payload(ssl_down, msg_buf, &msg_len, ml_buf, &ml_len) < 0) {
            fprintf(stderr, "[MB] Error receiving client message in round #2.\n");
            goto mb_cleanup;
        }
        {
            char *copy1;
            SAFE_STRDUP(copy1, (char*)ml_buf);
            char *token = strtok(copy1, "|");
            if (token != NULL) { 
                element_set_str(h1, token, 10);
                token = strtok(NULL, "|");
            }
            if (token != NULL) { 
                element_set_str(temp1, token, 10);
                token = strtok(NULL, "|");
            }
            pairing_apply(temp2, h1, Sign_public_key, pairing);
            if (!element_cmp(temp1, temp2)) {
                log_printf("Sig verified");
            } else {
                log_printf("Sig not verified");
            }
            free(copy1);
        }
        unsigned char mb_out[BUFFER_SIZE];
        size_t mb_out_len = sizeof(mb_out);
        if (append_tag(" [updated_by_MB]", msg_buf, msg_len, mb_out, &mb_out_len) < 0) {
            fprintf(stderr, "[MB] append_tag fail.\n");
            goto mb_cleanup;
        }
        log_printf("\n=== [MB -> Server] ===\n");
        log_printf("MB's message:\n  %s\n", mb_out);

        unsigned char sig[8192] = {0};
        int sig_len = generate_sanitizable_signature(mb_out, mb_out_len, sig, sizeof(sig));
        if (send_payload(ssl_up, mb_out, mb_out_len, sig, sig_len) < 0) {
            fprintf(stderr, "[MB] send_payload to server failed.\n");
            goto mb_cleanup;
        }
        log_printf("[MB] Forwarded message+ML to Server.\n");

        unsigned char srv_msg[BUFFER_SIZE], srv_ml[BUFFER_SIZE];
        size_t srv_msg_len=0, srv_ml_len=0;
        if (recv_payload(ssl_up, srv_msg, &srv_msg_len, srv_ml, &srv_ml_len) < 0) {
            fprintf(stderr, "[MB] Error receiving server response.\n");
            goto mb_cleanup;
        }
        {
            char *copy1;
            SAFE_STRDUP(copy1, (char*)srv_ml);
            char *token = strtok(copy1, "|");
            if (token != NULL) { 
                element_set_str(h1, token, 10);
                token = strtok(NULL, "|");
            }
            if (token != NULL) { 
                element_set_str(temp1, token, 10);
                token = strtok(NULL, "|");
            }
            pairing_apply(temp2, h1, Sign_public_key, pairing);
            if (!element_cmp(temp1, temp2)) {
                log_printf("m1 signature verifies\n");
            } else {
                log_printf("m1 signature does not verify\n");
            }
            free(copy1);
        }
        unsigned char mb_out2[BUFFER_SIZE];
        size_t mb_out2_len = sizeof(mb_out2);
        if (append_tag(" [updated_by_MB]", srv_msg, srv_msg_len, mb_out2, &mb_out2_len) < 0) {
            fprintf(stderr, "[MB] fail append_tag for response.\n");
            goto mb_cleanup;
        }
        log_printf("\n=== [MB -> Client] ===\n");
        log_printf("MB's message:\n  %.*s\n", (int)mb_out2_len, mb_out2);
        log_printf("MB's message:\n  %s\n", mb_out2);

        unsigned char sig1[8192] = {0};
        int sig_len1 = generate_sanitizable_signature(mb_out, mb_out_len, sig1, sizeof(sig1));
        if (send_payload(ssl_down, mb_out2, mb_out2_len, sig1, sig_len1) < 0) {
            fprintf(stderr, "[MB] send_payload to client fail.\n");
            goto mb_cleanup;
        }
        log_printf("[MB] Forwarded final response to client.\n");
    }

mb_cleanup:
    SSL_shutdown(ssl_down);
    SSL_free(ssl_down);
    close(client_fd);
    close(listen_fd);
    SSL_shutdown(ssl_up);
    SSL_free(ssl_up);
    close(up_fd);
    SSL_CTX_free(ctx_down);
    SSL_CTX_free(ctx_up);
    log_printf("[MB] Done.\n");
    return;
mb_fail:
    if (up_fd >= 0) close(up_fd);
    SSL_CTX_free(ctx_up);
    return;
}

char* load_param(const char *filename, long *len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    *len = ftell(fp);
    rewind(fp);

    char *buf = (char*)malloc(*len + 1);
    CHECK_ALLOC(buf);
    fread(buf, 1, *len, fp);
    buf[*len] = '\0';
    fclose(fp);
    return buf;
}

static void run_client(const char *mb_host, int mb_port) {
    SSL_CTX *ctx = create_context_client();
    int sockfd = create_client_socket(mb_host, mb_port);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[Client] SSL_connect to MB failed.\n");
        ERR_print_errors_fp(stderr);
        goto client_cleanup;
    }
    log_printf("[Client] TLS handshake complete with MB.\n");

    element_random(g1);
    element_random(Sign_secret_key);
    element_pow_zn(Sign_public_key, g1, Sign_secret_key);
    element_random(g2);
    element_random(San_secret_key);
    element_pow_zn(San_public_key, g2, San_secret_key);

    char *result = (char *)malloc(8192);
    CHECK_ALLOC(result);
    result[0] = '\0';

    {
        // Replacing repeated code with macro for printing/serializing
        SNPRINT_AND_APPEND(result, g1);
        SNPRINT_AND_APPEND(result, h1);
        SNPRINT_AND_APPEND(result, Sign_public_key);
        SNPRINT_AND_APPEND(result, Sign_secret_key);
        SNPRINT_AND_APPEND(result, sig_Fix);
        SNPRINT_AND_APPEND(result, temp1);
        SNPRINT_AND_APPEND(result, temp2);
        SNPRINT_AND_APPEND(result, g2);
        SNPRINT_AND_APPEND(result, h2);
        SNPRINT_AND_APPEND(result, San_public_key);
        SNPRINT_AND_APPEND(result, San_secret_key);
        SNPRINT_AND_APPEND(result, sig_FULL);
        SNPRINT_AND_APPEND(result, temp3);
        // For the last element, don't append delimiter:
        {
            char temp[1024];
            element_snprint(temp, sizeof(temp), temp4);
            strcat(result, temp);
        }
    }

    int len = (int)strlen(result);
    int r = SSL_write(ssl, result, len);
    free(result);

    if (r != len) {
        fprintf(stderr, "[Client] Failed to send Key.\n");
        goto client_cleanup;
    }
    log_printf("[Client] Sent key to MB.\n");
    print_keys(); // Example usage

    {
        char input_buf[256];
        log_printf("Type a message to send to the server:\n");
        if (!fgets(input_buf, sizeof (input_buf), stdin)) {
            strcpy(input_buf, "Hello Server!\n");
        }
        size_t input_len = strlen(input_buf);
        Timer timer;
        start_timer(&timer);

        unsigned char sig[8192] = {0};
        int sig_len = generate_signature(input_buf, input_len, sig, sizeof(sig));
        if (send_payload(ssl, (unsigned char*)input_buf, input_len, sig, sig_len) < 0) {
            fprintf(stderr, "[Client] send_payload fail.\n");
            goto client_cleanup;
        }
        log_printf("[Client] Sent message+empty ML to MB.\n");

        unsigned char msg_buf[BUFFER_SIZE], ml_buf[BUFFER_SIZE];
        size_t msg_len=0, ml_len=0;
        if (recv_payload(ssl, msg_buf, &msg_len, ml_buf, &ml_len) < 0) {
            fprintf(stderr, "[Client] Error receiving final response.\n");
            goto client_cleanup;
        }
        {
            char *copy1;
            SAFE_STRDUP(copy1, (char*)ml_buf);
            char *token = strtok(copy1, "|");
            if (token != NULL) { 
                element_set_str(h2, token, 10);
                token = strtok(NULL, "|");
            }
            if (token != NULL) { 
                element_set_str(temp3, token, 10);
                token = strtok(NULL, "|");
            }
            pairing_apply(temp4, h2, San_public_key, pairing);
            if (!element_cmp(temp3, temp4)) {
                log_printf("FULL signature verifies\n");
            } else {
                log_printf("FULL signature does not verify\n");
            }
            free(copy1);
        }
        double elapsed_gen = stop_timer(&timer);
        printf("Time taken RTT: %.3f ms\n", elapsed_gen);
        log_printf("\n=== [Client Received Final Response] ===\n");
    }

client_cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    log_printf("[Client] Done.\n");
}

int main(int argc, char **argv) {
    init_openssl_library();
    long p_len;
    char *p_str = load_param("param_a.txt", &p_len);
    pairing_init_set_buf(pairing, p_str, p_len);

    element_init_G2(g1, pairing);
    element_init_G2(Sign_public_key, pairing);
    element_init_G1(h1, pairing);
    element_init_G1(sig_Fix, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_Zr(Sign_secret_key, pairing);

    element_init_G2(g2, pairing);
    element_init_G2(San_public_key, pairing);
    element_init_G1(h2, pairing);
    element_init_G1(sig_FULL, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_Zr(San_secret_key, pairing);

    int set_log = 1;
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s server <port> <cert> <key>\n", argv[0]);
        fprintf(stderr, "  %s middlebox <port> <srv_host> <srv_port> <cert> <key>\n", argv[0]);
        fprintf(stderr, "  %s client <mb_host> <mb_port>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "server") == 0) {
        if (argc != 6) {
            fprintf(stderr, "server mode: <port> <cert> <key>\n");
            return 1;
        }
        int port = atoi(argv[2]);
        logger_init(argv[5], set_log);
        run_server(port, argv[3], argv[4]);
    } else if (strcmp(argv[1], "middlebox") == 0) {
        if (argc != 8) {
            fprintf(stderr, "middlebox mode: <port> <srv_host> <srv_port> <cert> <key>\n");
            return 1;
        }
        int listen_port = atoi(argv[2]);
        const char *srv_host = argv[3];
        int srv_port = atoi(argv[4]);
        logger_init(argv[7], set_log);
        run_middlebox(listen_port, srv_host, srv_port, argv[5], argv[6]);
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc != 5) {
            fprintf(stderr, "client mode: <mb_host> <mb_port>\n");
            return 1;
        }
        const char *mb_host = argv[2];
        int mb_port = atoi(argv[3]);
        logger_init(argv[4], set_log);
        run_client(mb_host, mb_port);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
