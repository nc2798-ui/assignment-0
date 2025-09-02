/******************************
File Name: homework0.c
Assignment: 0
Description: Prints the SHA256 hashed "flag" based on a salted email.
******************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

// Declare a constant string for the user's email address
const char EMAIL_ADDRESS[] = "nc2798@nyu.edu"; // Replace with your email

// Function to generate a SHA256 hash
void generate_sha256_flag(const char *email, const char *salt, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char input[512]; // Buffer to combine email and salt
    int i;

    // Combine the email and salt into the input buffer
    snprintf(input, sizeof(input), "%s%s", email, salt);

    // Compute the SHA256 hash
    SHA256((unsigned char *)input, strlen(input), hash);

    // Convert the hash to a hexadecimal string
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
    }

    // Null-terminate the output string
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int main() {
    char flag[SHA256_DIGEST_LENGTH * 2 + 1]; // Buffer to store the flag (hex string)
    char salt[256]; // Buffer to store the salt read from the file
    FILE *salt_file;

    // Open the salt file for reading
    salt_file = fopen("assignment_salt.txt", "r");
    if (!salt_file) {
        perror("Error opening salt file");
        return EXIT_FAILURE;
    }

    // Read the salt from the file
    if (!fgets(salt, sizeof(salt), salt_file)) {
        perror("Error reading salt file");
        fclose(salt_file);
        return EXIT_FAILURE;
    }

    // Remove trailing newline character if present
    size_t len = strlen(salt);
    if (len > 0 && salt[len - 1] == '\n') {
        salt[len - 1] = '\0';
    }

    fclose(salt_file);

    // Generate the hashed flag
    generate_sha256_flag(EMAIL_ADDRESS, salt, flag);

    // Print the email address and the flag
    printf("Email address: %s\n", EMAIL_ADDRESS);
    printf("Your flag is: %s\n", flag);

    return 0;
}

