#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#endif /* __PROGTEST__ */

int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    if (bits < 0) return 0;
    
    // Allocate memory for the digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (ctx == NULL) return 0;
    
    // Set the digest type
    OpenSSL_add_all_digests();
    const EVP_MD* sha = EVP_get_digestbyname(hashFunction);
    if (sha == NULL) {
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    
    if (bits > EVP_MD_size(sha)) {
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    
    int res;
    unsigned long long counter = 0;
    std::string data;
    unsigned int message_length;
    int hash_length = EVP_MD_size(sha);
    unsigned char* digest = (unsigned char *)malloc(hash_length);
    if (digest == NULL) {
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    bool found = false;

    srand(time(NULL));
    while (!found) {
        // Generate a random message to hash, with length up to 10000 bytes
        counter += 1;
        data = std::to_string(counter);
        message_length = data.size();

        // Compute the hash of the current message
        res = EVP_DigestInit_ex(ctx, sha, NULL);
        if (res != 1) {
            free(digest);
            EVP_MD_CTX_destroy(ctx);
            return 0;
        }
        res = EVP_DigestUpdate(ctx, data.c_str(), message_length);
        if (res != 1) {
            free(digest);
            EVP_MD_CTX_destroy(ctx);
            return 0;
        }
        res = EVP_DigestFinal_ex(ctx, digest, NULL);
        if (res != 1) {
            free(digest);
            EVP_MD_CTX_destroy(ctx);
            return 0;
        }

        // Check the number of leading zero bits
        bool success = true;
        for (int i = 0; i < bits / 8 && success; ++i) {
            if (digest[i] != 0) success = false;
        }
        if (success && (bits % 8) != 0) {
            char mask = 0xFF << (8 - (bits % 8));
            if ((digest[bits / 8] & mask) == 0) found = true;
        }
        else if (success) found = true;
    }

    // Convert the data and the digest to hex strings
    *message = (char*)malloc(message_length * 2 + 1);
    if (*message == NULL) {
        free(digest);
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    *hash = (char*)malloc(hash_length * 2 + 1);
    if (*hash == NULL) {
        free(digest);
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    for (unsigned int i = 0, j = 0; i < message_length; ++i, j += 2) sprintf(*message + j, "%02x", data.c_str()[i]);
    for (int i = 0, j = 0; i < hash_length; ++i, j += 2) sprintf(*hash + j, "%02x", digest[i]);
    (*message)[message_length * 2] = '\0';
    (*hash)[hash_length * 2] = '\0';

    // Free the buffers and the context
    free(digest);
    EVP_MD_CTX_destroy(ctx);
    
    return 1;
}

int findHash (int bits, char ** message, char ** hash) {
    return findHashEx(bits, message, hash, "SHA512");
}

#ifndef __PROGTEST__

int checkHash(int bits, char * hexString) {
    // DIY
    int len = strlen(hexString) / 2;
    unsigned char* bytes = (unsigned char *)malloc(len);
    if (bytes == NULL) return 0;
    for (int i = 0; i < len; ++i) sscanf(&hexString[2 * i], "%2hhx", &bytes[i]);
    int success = 1;
    for (int i = 0; i < bits / 8 && success; ++i) {
        if (bytes[i] != 0) success = 0;
    }
    if (success && (bits % 8) != 0) {
        char mask = 0xFF << (8 - (bits % 8));
        if ((bytes[bits / 8] & mask) != 0) success = 0;
    }
    free(bytes);
    return success;
}

int main (void) {
    char * message, * hash;
    assert(findHash(0, &message, &hash) == 1);
    assert(message && hash && checkHash(0, hash));
    free(message);
    free(hash);
    assert(findHash(1, &message, &hash) == 1);
    assert(message && hash && checkHash(1, hash));
    free(message);
    free(hash);
    assert(findHash(2, &message, &hash) == 1);
    assert(message && hash && checkHash(2, hash));
    free(message);
    free(hash);
    assert(findHash(3, &message, &hash) == 1);
    assert(message && hash && checkHash(3, hash));
    free(message);
    free(hash);
    assert(findHash(-1, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

