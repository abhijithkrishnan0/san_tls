#include <pbc/pbc.h>
#include <stdio.h>

int main() {
    pbc_param_t param;
    pairing_t pairing;

    // Generate Type A pairing parameters
    pbc_param_init_a_gen(param, 160, 512);

    // Save the parameters to a file
    FILE *param_file = fopen("param_a.txt", "w");
    if (!param_file) {
        perror("fopen");
        return 1;
    }
    pbc_param_out_str(param_file, param);
    fclose(param_file);

    // // Read the parameters back from the file
    // param_file = fopen("param_a.txt", "r");
    // if (!param_file) {
    //     perror("fopen");
    //     return 1;
    // }
    // pbc_param_init(param);
    // if (pbc_param_in_str(param, param_file)) {
    //     fprintf(stderr, "Error reading parameters from file\n");
    //     fclose(param_file);
    //     return 1;
    // }
    // fclose(param_file);

    // // Initialize the pairing using the parameters
    // if (pairing_init_pbc_param(pairing, param)) {
    //     fprintf(stderr, "pairing_init_pbc_param failed\n");
    //     return 1;
    // }

    // // You can now use the pairing as needed...
    // element_t g, h, result;

    // // Initialize elements
    // element_init_G1(g, pairing);
    // element_init_G1(h, pairing);
    // element_init_GT(result, pairing);

    // // Set g and h to random elements
    // element_random(g);
    // element_random(h);

    // // Compute pairing
    // pairing_apply(result, g, h, pairing);

    // // Print result
    // element_printf("e(g, h) = %B\n", result);

    // // Clear elements and pairing
    // element_clear(g);
    // element_clear(h);
    // element_clear(result);
    // pairing_clear(pairing);
    // pbc_param_clear(param);

    return 0;
}
