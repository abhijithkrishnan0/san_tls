#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbc/pbc.h>
#include <sys/time.h>

char* concat_and_format(int size_1, char* m_1, int size_2, char* m_2) {
    int total_size = size_1 + size_2;
    int formatted_length = snprintf(NULL, 0, "[%d,%d,%d,%s,%s]", total_size, size_1, size_2, m_1, m_2) + 1;
    char* result = (char*)malloc(formatted_length);
    if (result == NULL) {
        perror("Failed to allocate memory");
        exit(1);
    }
    snprintf(result, formatted_length, "[%d,%d,%d,%s,%s]", total_size, size_1, size_2, m_1, m_2);
    return result;
}

void split_message(char* message, int* size_1, char** m_1, int* size_2, char** m_2) {
    sscanf(message, "[%*d,%d,%d", size_1, size_2);
    char* temp = strstr(message, ",");
    temp = strstr(temp + 1, ",") + 1;
    temp = strstr(temp + 1, ",") + 1;

    *m_1 = (char*)malloc(*size_1 + 1);
    strncpy(*m_1, temp, *size_1);
    (*m_1)[*size_1] = '\0';

    temp += *size_1 + 1;
    *m_2 = (char*)malloc(*size_2 + 1);
    strncpy(*m_2, temp, *size_2);
    (*m_2)[*size_2] = '\0';
}

char* update_message(char* concated_message, int size_3, char* m_3) {
    int size_1, size_2;
    char *m_1, *m_2;
    sscanf(concated_message, "[%*d,%d,%d", &size_1, &size_2);
    m_1 = (char*)malloc(size_1 + 1);
    char* temp = strstr(concated_message, ",");
    temp = strstr(temp + 1, ",") + 1;
    temp = strstr(temp + 1, ",") + 1;

    strncpy(m_1, temp, size_1);
    m_1[size_1] = '\0';

    int new_total_size = size_1 + size_3;
    int new_message_length = snprintf(NULL, 0, "[%d,%d,%d,%s,%s]", new_total_size, size_1, size_3, m_1, m_3) + 1;
    char* new_message = (char*)malloc(new_message_length);
    snprintf(new_message, new_message_length, "[%d,%d,%d,%s,%s]", new_total_size, size_1, size_3, m_1, m_3);

    free(m_1);
    return new_message;
}



int main(void){


    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);



    element_t g1, h1;
    element_t Sign_public_key, Sign_secret_key;
    element_t sig_Fix;
    element_t temp1, temp2;

    element_init_G2(g1, pairing);
    element_init_G2(Sign_public_key, pairing);
    element_init_G1(h1, pairing);
    element_init_G1(sig_Fix, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_Zr(Sign_secret_key, pairing);

    element_random(g1);
    element_random(Sign_secret_key);
    element_pow_zn(Sign_public_key, g1, Sign_secret_key);


    element_t g2, h2;
    element_t San_public_key, San_secret_key;
    element_t sig_FULL;
    element_t temp3, temp4;

    element_init_G2(g2, pairing);
    element_init_G2(San_public_key, pairing);
    element_init_G1(h2, pairing);
    element_init_G1(sig_FULL, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_Zr(San_secret_key, pairing);

    element_random(g2);
    element_random(San_secret_key);
    element_pow_zn(San_public_key, g2, San_secret_key);


    int size1 = 5, size2 = 6, size3 = 7;
    char* m1 = "Hello";
    char* m2 = "World!";
    char* m3 = "Welcome";

    element_from_hash(h1, m1, size1);
    element_pow_zn(sig_Fix, h1, Sign_secret_key);


    pairing_apply(temp1, sig_Fix, g1, pairing);
    pairing_apply(temp2, h1, Sign_public_key, pairing);
    if (!element_cmp(temp1, temp2)) {
        printf("m1 signature verifies\n");
    } else {
        printf("m1 signature does not verify\n");
    }
    
    char* message = concat_and_format(size1, m1, size2, m2);
    printf("Original Message: %s\n", message);


    char* updated_message = update_message(message, size3, m3);
    printf("Updated Message: %s\n", updated_message);

    element_from_hash(h2, updated_message, size1+size3);
    element_pow_zn(sig_FULL, h2, San_secret_key);

    

    pairing_apply(temp3, sig_FULL, g2, pairing);
    pairing_apply(temp4, h2, San_public_key, pairing);

    if (!element_cmp(temp3, temp4)) {
        printf("FULL signature verifies\n");
    } else {
        printf("FULL signature does not verify\n");
    }


    return 0;
}