#!/usr/bin/env bash

gcc -I. -I./libwally-core/include -I./libwally-core/src ./ccan/ccan/crypto/hkdf_sha256/hkdf_sha256.o ./ccan/ccan/crypto/sha256/sha256.o ./ccan/ccan/crypto/hmac_sha256/hmac_sha256.o ccan/ccan/read_write_all/read_write_all.o main.c -lwallycore -o lightning-xpriv

