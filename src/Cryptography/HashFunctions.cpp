#include "../../include/Utils/Common.h"
#include "../../include/Cryptography/HashFunctions.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include "../../src/Cryptography/argon2/src/blake2/blake2.h"

HashFunctions::HashFunctions()
{
}

HashFunctions::~HashFunctions()
{
}

string HashFunctions::getHash(const string &input, string hashFunctionName, string format)
{
    EVP_MD_CTX *mdctx;
    unsigned char *hash;
    unsigned int hashLength;
    const EVP_MD *evp_mdAlgorithm;
    string hashStr = "";

    stringToLowercase(hashFunctionName);
    stringToLowercase(format);

    if (hashFunctionName == "blake2b" || hashFunctionName == "blake2b-512")
    {
        hashLength = BLAKE2B_OUTBYTES;
        hash = (unsigned char*)malloc(hashLength * sizeof(unsigned char));

        blake2b(hash, hashLength, input.c_str(), (unsigned long long)input.length(), NULL, 0);
    }
    else if (hashFunctionName == "blake2b-256")
    {
        hashLength = 32;
        hash = (unsigned char*)malloc(hashLength * sizeof(unsigned char));

        blake2b(hash, hashLength, input.c_str(), (unsigned long long)input.length(), NULL, 0);
    }
    else
    {
        evp_mdAlgorithm = EVP_get_digestbyname(hashFunctionName.c_str());

        if((mdctx = EVP_MD_CTX_new()) == NULL)
            return ""; // Error handling...

        if(EVP_DigestInit_ex(mdctx, evp_mdAlgorithm, NULL) != 1)
            return ""; // Error handling...

        if(EVP_DigestUpdate(mdctx, input.c_str(), input.length()) != 1)
            return ""; // Error handling...

        if((hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(evp_mdAlgorithm))) == NULL)
            return ""; // Error handling...

        if(EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1)
            return ""; // Error handling...

        EVP_MD_CTX_free(mdctx);
    }

    if (format == "hex")
    {
        stringstream ss;

        for(int i = 0; i < hashLength; i++)
        {
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        
        hashStr = ss.str();
        stringToUppercase(hashStr);

        free(hash);
        return hashStr;
    }
    else if (format == "base64")
    {
        size_t outputLength;
        char *base64;

        build_decoding_table();
        base64 = base64_encode(hash, hashLength, &outputLength);
        base64_cleanup();
        free(hash);
        
        return base64;
    }
    else
    {
        stringstream ss;

        for(int i = 0; i < hashLength; i++)
        {
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        
        hashStr = ss.str();
        stringToUppercase(hashStr);

        free(hash);
        return hashStr;
    }
}

unsigned char* HashFunctions::getHash(unsigned char *input, size_t inputLength, string hashFunctionName)
{
    EVP_MD_CTX *mdctx;
    unsigned char *hash;
    unsigned int hashLength;
    const EVP_MD *evp_mdAlgorithm;
    string hashStr = "";

    stringToLowercase(hashFunctionName);

    if (hashFunctionName == "blake2b" || hashFunctionName == "blake2b-512")
    {
        hashLength = BLAKE2B_OUTBYTES;
        hash = (unsigned char*)malloc(hashLength * sizeof(unsigned char));

        blake2b(hash, hashLength, input, (unsigned long long)strlen((char*)input), NULL, 0);
    }
    else if (hashFunctionName == "blake2b-256")
    {
        hashLength = 32;
        hash = (unsigned char*)malloc(hashLength * sizeof(unsigned char));

        blake2b(hash, hashLength, input, (unsigned long long)strlen((char*)input), NULL, 0);
    }
    else
    {
        evp_mdAlgorithm = EVP_get_digestbyname(hashFunctionName.c_str());

        if((mdctx = EVP_MD_CTX_new()) == NULL)
            return NULL; // Error handling...

        if(EVP_DigestInit_ex(mdctx, evp_mdAlgorithm, NULL) != 1)
            return NULL; // Error handling...

        if(EVP_DigestUpdate(mdctx, input, inputLength) != 1)
            return NULL; // Error handling...

        if((hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(evp_mdAlgorithm))) == NULL)
            return NULL; // Error handling...

        if(EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1)
            return NULL; // Error handling...

        EVP_MD_CTX_free(mdctx);

        unsigned char *hashTemp = (unsigned char*)malloc(hashLength * sizeof(unsigned char));
        memcpy(hashTemp, hash, hashLength);

        free(hash);
        
        hash = (unsigned char*)malloc(hashLength * sizeof(unsigned char));
        memcpy(hash, hashTemp, hashLength);

        free(hashTemp);
    }

    return hash;
}