#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>


#include<wally_bip32.h>
#include<ccan/ccan/read_write_all/read_write_all.h>
#include<ccan/ccan/crypto/hkdf_sha256/hkdf_sha256.h>

void bip_32_seed_from_hsm_secret(const uint8_t *hsm_secret, const bool testnet, struct ext_key *master_extkey)
{
    uint32_t salt = 0;
    uint32_t version = testnet ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;
    uint8_t bip32_seed[BIP32_ENTROPY_LEN_256];

    do {
		hkdf_sha256(bip32_seed, sizeof(bip32_seed),
			    &salt, sizeof(salt),
			    &hsm_secret, sizeof(hsm_secret),
			    "bip32 seed", strlen("bip32 seed"));
		salt++;
	} while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
				     version, 0, master_extkey) != WALLY_OK);
}

int main (int argc, char **argv)
{
    int opt, fd;
    char *hsm_secret_path;
    char *encoded_xpriv;
    uint8_t hsm_secret[32];
    bool testnet = false;
    struct ext_key master_extkey;

    while ((opt = getopt(argc, argv, "s:th")) != -1) {
    switch (opt) {
        case 's':
            hsm_secret_path = optarg;
            break;
        case 't':
            testnet = !testnet;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s -s /path/to/hsmssecret\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // get the hsm secret
	fd = open(hsm_secret_path, O_RDONLY);
	if (fd < 0) {
        printf( "Could not open hsm_secret\n");
        return 1;
    }

    if (read_all(fd, hsm_secret, sizeof(*hsm_secret))) {
        // derive seed and master key
        bip_32_seed_from_hsm_secret(hsm_secret, testnet, &master_extkey);
        if (bip32_key_to_base58(&master_extkey, BIP32_FLAG_KEY_PRIVATE, &encoded_xpriv) != WALLY_OK) {
            printf("Failed to encode xpriv");
            return 1;
        } else {
            printf("%s\n", encoded_xpriv);
        }
    }    
}

