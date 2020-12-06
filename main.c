#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>

#include <wally_bip32.h>
#include <ccan/ccan/crypto/hkdf_sha256/hkdf_sha256.h>

/* snippets inspired from:
 * https://github.com/ElementsProject/lightning/blob/master/tools/hsmtool.c
 * This was a script written to recover my lightning wallet xpriv to use it in a descriptor
 * Use with extreme caution
 */

void bip_32_seed_from_hsm_secret(const unsigned char** hsm_buffer, size_t hsm_buffer_len, const bool mainnet, struct ext_key* master_extkey)
{
    uint32_t salt = 0;
    uint32_t version = mainnet ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
    uint8_t bip32_seed[BIP32_ENTROPY_LEN_256];

    do {
        hkdf_sha256(bip32_seed, sizeof(bip32_seed),
            &salt, sizeof(salt),
            *hsm_buffer, hsm_buffer_len,
            "bip32 seed", strlen("bip32 seed"));
        salt++;
    } while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
                 version, 0, master_extkey)
        != WALLY_OK);
}

int main(int argc, char** argv)
{
    int opt;
    bool mainnet = false;
    char* hsm_secret_path;
    FILE* f;
    unsigned char* hsm_buffer;
    size_t len;
    struct ext_key master_extkey;
    char* encoded_xpriv;

    while ((opt = getopt(argc, argv, "s:m")) != -1) {
        switch (opt) {
        case 's':
            hsm_secret_path = optarg;
            break;
        case 'm':
            mainnet = !mainnet;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s -s /path/to/hsmssecret [-m]\n-m\t enable mainnet",
                argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    f = fopen(hsm_secret_path, "rb");
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    rewind(f);
    hsm_buffer = (char*)malloc(len * sizeof(char));
    fread(hsm_buffer, len, 1, f);
    fclose(f);

    // derive seed and master key
    bip_32_seed_from_hsm_secret(&hsm_buffer, len, mainnet, &master_extkey);
    if (bip32_key_to_base58(&master_extkey, BIP32_FLAG_KEY_PRIVATE, &encoded_xpriv) != WALLY_OK) {
        printf("Failed to encode xpriv");
        return 1;
    }
    else {
        printf("%s\n", encoded_xpriv);
        return 0;
    }
}
