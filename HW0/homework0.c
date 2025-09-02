/******************************
File Name: homework0.c
Assignment: 0
Description: Prints the SHA256 hashed "flag" based on a salted email.
******************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

const char EMAIL_ADDRESS[] = "nc2798@nyu.edu";

static void generate_sha256_flag(const char *email, const char *salt, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char input[512]; // email + salt
    snprintf(input, sizeof(input), "%s%s", email, salt);
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

static int read_salt_into(char *buf, size_t bufsz, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    if (!fgets(buf, bufsz, fp)) { fclose(fp); return 0; }
    fclose(fp);
    // trim trailing newline or CRLF
    size_t n = strlen(buf);
    while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) { buf[--n] = '\0'; }
    return 1;
}

int main(int argc, char **argv) {
    char salt[256];
    const char *candidates[] = {
        argc > 1 ? argv[1] : NULL,
        "HW0/assignment_salt.txt",
        "assign_0/HW0/assignment_salt.txt",
        "./assignment_salt.txt",
        NULL
    };

    int ok = 0;
    for (int i = 0; candidates[i]; i++) {
        if (candidates[i] && read_salt_into(salt, sizeof(salt), candidates[i])) { ok = 1; break; }
    }
    if (!ok) {
        fprintf(stderr, "Error opening salt file\n");
        return EXIT_FAILURE;
    }

    char flag[SHA256_DIGEST_LENGTH * 2 + 1];
    generate_sha256_flag(EMAIL_ADDRESS, salt, flag);

    // print only the hash followed by a newline
    puts(flag);
    return 0;
}
