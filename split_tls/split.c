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

#include "timer.h"
#include "logger.h"

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
        fprintf(stderr, "Unable to create SSL server context.\n");
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
        fprintf(stderr, "Unable to create SSL client context.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

static int create_listen_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket() failed");
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("bind() failed");
    if (listen(sockfd, 1) < 0)
        die("listen() failed");
    return sockfd;
}

static int create_client_socket(const char *host, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket() failed");
    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &srv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address or address not supported: %s\n", host);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if (connect(sockfd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0)
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

static int send_message(SSL *ssl, const unsigned char *data, size_t len) {
    unsigned char header[8];
    memset(header, 0, sizeof(header));
    write_u32(header, (uint32_t)len);
    int r = SSL_write(ssl, header, 8);
    if (r != 8) {
        fprintf(stderr, "send_message: failed to write 8-byte header.\n");
        return -1;
    }
    r = SSL_write(ssl, data, (int)len);
    if (r != (int)len) {
        fprintf(stderr, "send_message: partial write.\n");
        return -1;
    }
    return 0;
}

static int recv_message(SSL *ssl, unsigned char *buf, size_t buf_size, size_t *out_len) {
    unsigned char header[8];
    int r = SSL_read(ssl, header, 8);
    if (r <= 0) {
        fprintf(stderr, "recv_message: error reading header.\n");
        return -1;
    }
    if (r < 8) {
        fprintf(stderr, "recv_message: partial header.\n");
        return -1;
    }
    uint32_t msg_len = read_u32(header);
    if (msg_len > buf_size) {
        fprintf(stderr, "recv_message: message too large.\n");
        return -1;
    }
    r = SSL_read(ssl, buf, msg_len);
    if (r < (int)msg_len) {
        fprintf(stderr, "recv_message: partial read of message.\n");
        return -1;
    }
    *out_len = msg_len;
    return 0;
}

static void run_server(int port, const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = create_context_server(cert_file, key_file);
    int listen_fd = create_listen_socket(port);
    log_printf("[Server] Listening on port %d ...\n", port);
    int mb_fd = accept(listen_fd, NULL, NULL);
    if (mb_fd < 0) {
        perror("accept() failed");
        close(listen_fd);
        SSL_CTX_free(ctx);
        return;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, mb_fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto srv_done;
    }
    log_printf("[Server] TLS handshake completed.\n");
    unsigned char buffer[1024];
    size_t msg_len = 0;
    if (recv_message(ssl, buffer, sizeof(buffer), &msg_len) == 0) {
        log_printf("[Server] Received message from MB: %.*s\n", (int)msg_len, buffer);
        const char *tag = " [Server Updated]";
        size_t tag_len = strlen(tag);
        if (msg_len + tag_len < sizeof(buffer)) {
            memcpy(buffer + msg_len, tag, tag_len);
            msg_len += tag_len;
            log_printf("[Server] Sending message back...\n");
            send_message(ssl, buffer, msg_len);
        }
    }
srv_done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(mb_fd);
    close(listen_fd);
    SSL_CTX_free(ctx);
    log_printf("[Server] Done.\n");
}

static void run_middlebox(int listen_port, const char *server_host, int server_port,
                          const char *cert_file, const char *key_file) {
    SSL_CTX *ctx_up = create_context_client();
    int srv_fd = create_client_socket(server_host, server_port);
    SSL *ssl_up = SSL_new(ctx_up);
    SSL_set_fd(ssl_up, srv_fd);
    if (SSL_connect(ssl_up) <= 0) {
        fprintf(stderr, "[MB] SSL_connect to server failed.\n");
        ERR_print_errors_fp(stderr);
        goto mb_done;
    }
    log_printf("[MB] Connected + TLS handshake with server.\n");
    SSL_CTX *ctx_down = create_context_server(cert_file, key_file);
    int listen_fd = create_listen_socket(listen_port);
    log_printf("[MB] Listening on port %d for client...\n", listen_port);
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("[MB] accept() failed");
        goto mb_done2;
    }
    SSL *ssl_down = SSL_new(ctx_down);
    SSL_set_fd(ssl_down, client_fd);
    if (SSL_accept(ssl_down) <= 0) {
        fprintf(stderr, "[MB] SSL_accept from client failed.\n");
        close(client_fd);
        goto mb_done2;
    }
    log_printf("[MB] TLS handshake with client done.\n");
    {
        unsigned char buffer[1024];
        size_t msg_len = 0;
        if (recv_message(ssl_down, buffer, sizeof(buffer), &msg_len) == 0) {
            log_printf("[MB] Received from client: %.*s\n", (int)msg_len, buffer);
            const char *tag = " [MB updated]";
            size_t tag_len = strlen(tag);
            if (msg_len + tag_len < sizeof(buffer)) {
                memcpy(buffer + msg_len, tag, tag_len);
                msg_len += tag_len;
            }
            log_printf("[MB] Forwarding to server...\n");
            send_message(ssl_up, buffer, msg_len);
            size_t resp_len = 0;
            if (recv_message(ssl_up, buffer, sizeof(buffer), &resp_len) == 0) {
                log_printf("[MB] Received response from server: %.*s\n", (int)resp_len, buffer);
                const char *tag2 = " [MB updated]";
                if (resp_len + strlen(tag2) < sizeof(buffer)) {
                    memcpy(buffer + resp_len, tag2, strlen(tag2));
                    resp_len += strlen(tag2);
                }
                log_printf("[MB] Forwarding response back to client...\n");
                send_message(ssl_down, buffer, resp_len);
            }
        }
        SSL_shutdown(ssl_down);
        SSL_free(ssl_down);
        close(client_fd);
    }
mb_done2:
    close(listen_fd);
    SSL_CTX_free(ctx_down);
    SSL_shutdown(ssl_up);
    SSL_free(ssl_up);
    close(srv_fd);
    SSL_CTX_free(ctx_up);
mb_done:
    log_printf("[MB] Done.\n");
}

static void run_client(const char *mb_host, int mb_port) {
    SSL_CTX *ctx = create_context_client();
    int sockfd = create_client_socket(mb_host, mb_port);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[Client] SSL_connect to MB failed.\n");
        ERR_print_errors_fp(stderr);
        goto cl_done;
    }
    log_printf("[Client] Connected + TLS handshake with MB.\n");
    char input[512];
    log_printf("Enter a message to send to the server: ");
    fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) {
        strcpy(input, "Hello from Client!\n");
    }
    size_t msg_len = strlen(input);
    Timer timer;
    start_timer(&timer);
    if (send_message(ssl, (unsigned char*)input, msg_len) == 0) {
        unsigned char buffer[1024];
        size_t resp_len = 0;
        if (recv_message(ssl, buffer, sizeof(buffer), &resp_len) == 0) {
            log_printf("[Client] Final response from server (via MB): %.*s\n",
                       (int)resp_len, buffer);
        }
        double elapsed_gen = stop_timer(&timer);
        printf("Time taken RTT: %.3f ms\n", elapsed_gen);
    }
cl_done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    log_printf("[Client] Done.\n");
}

int main(int argc, char **argv) {
    init_openssl_library();
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s server <port> <cert> <key>\n", argv[0]);
        fprintf(stderr, "  %s middlebox <port> <srv_host> <srv_port> <mb.crt> <mb.key>\n", argv[0]);
        fprintf(stderr, "  %s client <mb_host> <mb_port>\n", argv[0]);
        return 1;
    }
    int set_log = 0;
    if (strcmp(argv[1], "server") == 0) {
        if (argc != 6) {
            fprintf(stderr, "server mode requires: <port> <cert> <key>\n");
            return 1;
        }
        int port = atoi(argv[2]);
        logger_init(argv[5], set_log);
        run_server(port, argv[3], argv[4]);
    } else if (strcmp(argv[1], "middlebox") == 0) {
        if (argc != 8) {
            fprintf(stderr, "middlebox mode requires: <port> <srv_host> <srv_port> <cert> <key>\n");
            return 1;
        }
        int listen_port = atoi(argv[2]);
        const char *srv_host = argv[3];
        int srv_port = atoi(argv[4]);
        logger_init(argv[7], set_log);
        run_middlebox(listen_port, srv_host, srv_port, argv[5], argv[6]);
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc != 5) {
            fprintf(stderr, "client mode requires: <mb_host> <mb_port>\n");
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
