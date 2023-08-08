#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CBC 1

#define AES256 1

#include "aes.c"
#include "aes.h"

void encryptFile(FILE* input, FILE* output) {
    uint8_t buffer[64];
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    struct AES_ctx ctx;

    while (fread(buffer, 1, 64, input) == 64)
    {
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_encrypt_buffer(&ctx, buffer, 64);
        fwrite(buffer, 1, 64, output);
    }
}

void decryptFile(FILE* input, FILE* output) {
    uint8_t buffer[64];
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    struct AES_ctx ctx;

    while (fread(buffer, 1, 64, input) == 64)
    {
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_decrypt_buffer(&ctx, buffer, 64);
        fwrite(buffer, 1, 64, output);
    }
}

int main()
{
    const char* inputFile = "FOTA.txt";
    FILE* mainfile = fopen(inputFile, "rb");
    FILE* encryptedOutput = fopen("256_encrypted.txt", "wb");
    encryptFile(mainfile, encryptedOutput);
    fclose(encryptedOutput);
    FILE* encfile = fopen("256_encrypted.txt", "rb");
    FILE* decryptedOutput = fopen("256-decrpted.txt","wb");
    decryptFile(encfile,decryptedOutput);
    fclose(mainfile);
    fclose(encfile);
    fclose(decryptedOutput);
}