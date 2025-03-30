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
#include "logger.h"
#include "timer.h"

#define BUFFER_SIZE 4096
#define SHARED_KEY_SIZE 32
#define DIGEST_SIZE 32
#define ID_LEN 16

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
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind() failed");
    if (listen(sockfd, 5) < 0) die("listen() failed");
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
    memcpy(buf, message, msg_len);
    memcpy(buf + msg_len, ml, ml_len);
    log_printf("\nModification Log size %d", (int)ml_len);
    printf("\nModification Log size %zu", ml_len);
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
    r = SSL_read(ssl, tmp, to_read);
    if (r < (int)to_read) {
        fprintf(stderr, "recv_payload: partial read? got %d, needed %u\n", r, to_read);
        free(tmp);
        return -1;
    }
    memcpy(message, tmp, mlen);
    *msg_len = mlen;
    memcpy(ml, tmp + mlen, llen);
    *ml_len = llen;
    printf("\nRecieved Modification Log size %zu", *ml_len);
    log_printf("\nRecieved Modification Log size %zu", *ml_len);
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

static int generate_mod_log(const char *entity_id,
                            const unsigned char *in_msg, size_t in_len,
                            const unsigned char *out_msg, size_t out_len,
                            const unsigned char *shared_key, size_t key_len,
                            unsigned char *ml_buf, size_t ml_buf_size) {
    unsigned char in_digest[DIGEST_SIZE];
    unsigned char out_digest[DIGEST_SIZE];
    compute_sha256(in_msg, in_len, in_digest);
    compute_sha256(out_msg, out_len, out_digest);
    unsigned char concat[2 * DIGEST_SIZE];
    memcpy(concat, in_digest, DIGEST_SIZE);
    memcpy(concat + DIGEST_SIZE, out_digest, DIGEST_SIZE);
    unsigned char hmac_val[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len = 0;
    HMAC(EVP_sha256(), shared_key, (int)key_len, concat, 2*DIGEST_SIZE, hmac_val, &hmac_len);
    if ((ID_LEN + DIGEST_SIZE + hmac_len) > ml_buf_size) {
        fprintf(stderr, "generate_mod_log: ml_buf too small\n");
        return -1;
    }
    memset(ml_buf, 0, ml_buf_size);
    size_t used_id_len = strlen(entity_id);
    if (used_id_len > ID_LEN) used_id_len = ID_LEN;
    memcpy(ml_buf, entity_id, used_id_len);
    size_t offset = ID_LEN;
    memcpy(ml_buf + offset, out_digest, DIGEST_SIZE);
    offset += DIGEST_SIZE;
    memcpy(ml_buf + offset, hmac_val, hmac_len);
    offset += hmac_len;
    return (int)offset;
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    log_printf("%s [len=%zu]: ", label, len);
    for (size_t i=0; i<len; i++) log_printf("%02X", buf[i]);
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
    unsigned char shared_key[SHARED_KEY_SIZE];
    int r = SSL_read(ssl, shared_key, SHARED_KEY_SIZE);
    if (r != SHARED_KEY_SIZE) {
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
    log_printf("[Server] Inbound ML size: %zu\n", ml_len);
    unsigned char server_out[BUFFER_SIZE];
    size_t server_out_len = sizeof(server_out);
    if (append_tag(" [updated_by_Server]", msg_buf, msg_len, server_out, &server_out_len) < 0) {
        fprintf(stderr, "[Server] Could not append server tag.\n");
        goto cleanup;
    }
    unsigned char server_ml[BUFFER_SIZE];
    int server_ml_len = generate_mod_log("Server", msg_buf, msg_len, server_out, server_out_len,
                                         shared_key, SHARED_KEY_SIZE, server_ml, sizeof(server_ml));
    if (server_ml_len < 0) {
        fprintf(stderr, "[Server] Could not generate server ML.\n");
        goto cleanup;
    }
    unsigned char combined_ml[BUFFER_SIZE * 2];
    size_t combined_ml_len = ml_len + server_ml_len;
    memcpy(combined_ml, ml_buf, ml_len);
    memcpy(combined_ml + ml_len, server_ml, server_ml_len);
    log_printf("\n=== [Server -> MB] ===\n");
    log_printf("Server's message:\n  %.*s\n", (int)server_out_len, server_out);
    log_printf("New Server ML segment size=%d\n", server_ml_len);
    log_printf("Total ML size now=%zu\n", combined_ml_len);
    print_hex("Server ML segment", server_ml, server_ml_len);
    if (send_payload(ssl, server_out, server_out_len, combined_ml, combined_ml_len) < 0) {
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
    int r = SSL_read(ssl_down, shared_key, SHARED_KEY_SIZE);
    if (r != SHARED_KEY_SIZE) {
        fprintf(stderr, "[MB] Did not receive 32-byte key from client.\n");
        goto mb_cleanup;
    }
    log_printf("[MB] Received 32-byte key from Client.\n");
    r = SSL_write(ssl_up, shared_key, SHARED_KEY_SIZE);
    if (r != SHARED_KEY_SIZE) {
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
        log_printf("[MB] Inbound ML size from client: %zu\n", ml_len);
        unsigned char mb_out[BUFFER_SIZE];
        size_t mb_out_len = sizeof(mb_out);
        if (append_tag(" [updated_by_MB]", msg_buf, msg_len, mb_out, &mb_out_len) < 0) {
            fprintf(stderr, "[MB] append_tag fail.\n");
            goto mb_cleanup;
        }
        unsigned char mb_ml[BUFFER_SIZE];
        int mb_ml_len = generate_mod_log("MB", msg_buf, msg_len, mb_out, mb_out_len,
                                         shared_key, SHARED_KEY_SIZE, mb_ml, sizeof(mb_ml));
        if (mb_ml_len < 0) {
            fprintf(stderr, "[MB] generate_mod_log fail.\n");
            goto mb_cleanup;
        }
        unsigned char combined_ml[BUFFER_SIZE * 2];
        size_t combined_ml_len = ml_len + mb_ml_len;
        memcpy(combined_ml, ml_buf, ml_len);
        memcpy(combined_ml + ml_len, mb_ml, mb_ml_len);
        log_printf("\n=== [MB -> Server] ===\n");
        log_printf("MB's message:\n  %.*s\n", (int)mb_out_len, mb_out);
        log_printf("New MB->Server ML segment size=%d\n", mb_ml_len);
        log_printf("Total ML size now=%zu\n", combined_ml_len);
        print_hex("MB->Server ML segment", mb_ml, mb_ml_len);
        if (send_payload(ssl_up, mb_out, mb_out_len, combined_ml, combined_ml_len) < 0) {
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
        log_printf("[MB] Inbound ML size from server: %zu\n", srv_ml_len);
        unsigned char mb_out2[BUFFER_SIZE];
        size_t mb_out2_len = sizeof(mb_out2);
        if (append_tag(" [updated_by_MB]", srv_msg, srv_msg_len, mb_out2, &mb_out2_len) < 0) {
            fprintf(stderr, "[MB] fail append_tag for response.\n");
            goto mb_cleanup;
        }
        unsigned char mb_ml2[BUFFER_SIZE];
        int mb_ml2_len = generate_mod_log("MB", srv_msg, srv_msg_len, mb_out2, mb_out2_len,
                                          shared_key, SHARED_KEY_SIZE, mb_ml2, sizeof(mb_ml2));
        if (mb_ml2_len < 0) {
            fprintf(stderr, "[MB] Could not generate MB->Client ML.\n");
            goto mb_cleanup;
        }
        unsigned char combined_ml2[BUFFER_SIZE * 2];
        size_t combined_ml2_len = srv_ml_len + mb_ml2_len;
        memcpy(combined_ml2, srv_ml, srv_ml_len);
        memcpy(combined_ml2 + srv_ml_len, mb_ml2, mb_ml2_len);
        log_printf("\n=== [MB -> Client] ===\n");
        log_printf("MB's message:\n  %.*s\n", (int)mb_out2_len, mb_out2);
        log_printf("New MB->Client ML segment size=%d\n", mb_ml2_len);
        log_printf("Total ML size now=%zu\n", combined_ml2_len);
        print_hex("MB->Client ML segment", mb_ml2, mb_ml2_len);
        if (send_payload(ssl_down, mb_out2, mb_out2_len, combined_ml2, combined_ml2_len) < 0) {
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
    unsigned char shared_key[SHARED_KEY_SIZE];
    memset(shared_key, 0xAB, SHARED_KEY_SIZE);
    int r = SSL_write(ssl, shared_key, SHARED_KEY_SIZE);
    if (r != SHARED_KEY_SIZE) {
        fprintf(stderr, "[Client] Failed to send 32-byte key to MB.\n");
        goto client_cleanup;
    }
    log_printf("[Client] Sent 32-byte key to MB.\n");
    {
        char input_buf[256];
        log_printf("Type a message to send to the server:\n");
        if (!fgets(input_buf, sizeof(input_buf), stdin)) {
            strcpy(input_buf, "Hello Server!\n");
        }
        size_t input_len = strlen(input_buf);
        unsigned char empty_ml[1] = {0};
        Timer timer;
        start_timer(&timer);
        if (send_payload(ssl, (unsigned char*)input_buf, input_len, empty_ml, 0) < 0) {
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
        double elapsed_gen = stop_timer(&timer);
        printf("Time taken RTT: %.3f ms\n", elapsed_gen);
        log_printf("\n=== [Client Received Final Response] ===\n");
        log_printf("Final message content:\n  %.*s\n", (int)msg_len, msg_buf);
        if (ml_len > 0) {
            log_printf("Modification Log:\n");
            print_hex("  ML Data", ml_buf, ml_len);
        } else {
            log_printf("(No ML received?)\n");
        }
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
    int set_log = 1;
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s server <port> <cert> <key> <log_file>\n", argv[0]);
        fprintf(stderr, "  %s middlebox <port> <srv_host> <srv_port> <cert> <key> <log_file>\n", argv[0]);
        fprintf(stderr, "  %s client <mb_host> <mb_port> <log_file>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "server") == 0) {
        if (argc != 6) {
            fprintf(stderr, "server mode: <port> <cert> <key> <log_file>\n");
            return 1;
        }
        int port = atoi(argv[2]);
        logger_init(argv[5], set_log);
        run_server(port, argv[3], argv[4]);
    } else if (strcmp(argv[1], "middlebox") == 0) {
        if (argc != 8) {
            fprintf(stderr, "middlebox mode: <port> <srv_host> <srv_port> <cert> <key> <log_file>\n");
            return 1;
        }
        int listen_port = atoi(argv[2]);
        const char *srv_host = argv[3];
        int srv_port = atoi(argv[4]);
        logger_init(argv[7], set_log);
        run_middlebox(listen_port, srv_host, srv_port, argv[5], argv[6]);
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc != 5) {
            fprintf(stderr, "client mode: <mb_host> <mb_port> <log_file>\n");
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
