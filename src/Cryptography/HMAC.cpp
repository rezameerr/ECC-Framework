#include <iostream>
#include <sstream>
#include <stdio.h>
#include "../../include/Utils/Common.h"
#include "../../include/Cryptography/HMAC.h"

HMAC::HMAC()
{
}

HMAC::~HMAC()
{
}

HMAC::HMACHashFunctionEx HMAC::getHMACHashFunctionEx(HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction)
{
    HMAC::HMACHashFunctionEx hmacHashFunctionEx;
    
    hmacHashFunctionEx.hmacHashFunction = hmacHashFunction;
    
    switch (hmacHashFunctionEx.hmacHashFunction)
    {
    case HMAC::HMAC_HASH_FUNCTIONS::BLAKE2b:
        hmacHashFunctionEx.name = "BLAKE2b";
        hmacHashFunctionEx.blockSize = 128;
        hmacHashFunctionEx.hashSize = 64;
        break;
    
    case HMAC::HMAC_HASH_FUNCTIONS::BLAKE2b_256:
        hmacHashFunctionEx.name = "BLAKE2b";
        hmacHashFunctionEx.blockSize = 128;
        hmacHashFunctionEx.hashSize = 32;
        break;
    
    case HMAC::HMAC_HASH_FUNCTIONS::SHA3_512:
        hmacHashFunctionEx.name = "SHA3-512";
        hmacHashFunctionEx.blockSize = 72;
        hmacHashFunctionEx.hashSize = 64;
        break;
    
    case HMAC::HMAC_HASH_FUNCTIONS::SHA3_256:
        hmacHashFunctionEx.name = "SHA3-256";
        hmacHashFunctionEx.blockSize = 136;
        hmacHashFunctionEx.hashSize = 32;
        break;
    
    case HMAC::HMAC_HASH_FUNCTIONS::SHA_512:
        hmacHashFunctionEx.name = "SHA512";
        hmacHashFunctionEx.blockSize = 128;
        hmacHashFunctionEx.hashSize = 64;
        break;
    
    case HMAC::HMAC_HASH_FUNCTIONS::SHA_384:
        hmacHashFunctionEx.name = "SHA384";
        hmacHashFunctionEx.blockSize = 128;
        hmacHashFunctionEx.hashSize = 48;
        break;
    
    case HMAC::HMAC_HASH_FUNCTIONS::SHA_256:
        hmacHashFunctionEx.name = "SHA256";
        hmacHashFunctionEx.blockSize = 64;
        hmacHashFunctionEx.hashSize = 32;
        break;
    
    /* Insecure - Not Recommended
    case HMAC::HMAC_HASH_FUNCTIONS::SHA1:
        hmacHashFunctionEx.name = "SHA1";
        hmacHashFunctionEx.blockSize = 64;
        hmacHashFunctionEx.hashSize = 20;
        break;
        
    case HMAC::HMAC_HASH_FUNCTIONS::MD5:
        hmacHashFunctionEx.name = "MD5";
        hmacHashFunctionEx.blockSize = 64;
        hmacHashFunctionEx.hashSize = 16;
        break;
    */

    default:
        hmacHashFunctionEx.name = "BLAKE2b";
        hmacHashFunctionEx.blockSize = 64;
        hmacHashFunctionEx.hashSize = 64;
        break;
    }

    return hmacHashFunctionEx;
}

unsigned char* HMAC::getHMAC(string keyHex, string message, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction)
{
    unsigned char *inputMessage;
    size_t inputMessageSize;
    unsigned char *inputKey;
    size_t inputKeySize;
    unsigned char *key;
    size_t keySize;
    unsigned char *hash;
    unsigned char *oKeyPad;
    unsigned char *iKeyPad;
    
    unsigned char *buf1;
    size_t buf1Size;

    unsigned char *buf2;
    size_t buf2Size;
    
    unsigned char *buf1Hash;
    
    HMAC::HMACHashFunctionEx hmacHashFunctionEx = getHMACHashFunctionEx(hmacHashFunction);
    string hashFunctionName = hmacHashFunctionEx.name;
    stringToLowercase(hashFunctionName);

    inputMessageSize = message.length();
    inputMessage = (unsigned char *)malloc(inputMessageSize * sizeof(unsigned char));
    std::copy(message.cbegin(), message.cend(), inputMessage);

    inputKeySize = keyHex.length() / 2;
    //inputKey = (unsigned char *)malloc(inputKeySize * sizeof(unsigned char));
    inputKey = hexToByteArray(keyHex.c_str());
    
    keySize = hmacHashFunctionEx.blockSize;
    key = (unsigned char *)malloc(keySize * sizeof(unsigned char));
    hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));
    oKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));
    iKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));

    buf1Size = hmacHashFunctionEx.blockSize + inputMessageSize;
    buf2Size = hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize;

    buf1 = (unsigned char *)malloc(buf1Size * sizeof(unsigned char));
    buf2 = (unsigned char *)malloc(buf2Size * sizeof(unsigned char));

    buf1Hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));

    memset(key, 0x00, hmacHashFunctionEx.blockSize);
    memset(oKeyPad, 0x5c, hmacHashFunctionEx.blockSize);
    memset(iKeyPad, 0x36, hmacHashFunctionEx.blockSize);
    memset(buf1, 0x00, hmacHashFunctionEx.blockSize + inputMessageSize);
    memset(buf2, 0x00, hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize);

    if (inputKeySize > hmacHashFunctionEx.blockSize)
    {
        key = HashFunctions::getHash(inputKey, inputKeySize, hashFunctionName);
    }
    else
    {
        memcpy(key, inputKey, inputKeySize);
    }

    free(inputKey);

    for (int i = 0; i < hmacHashFunctionEx.blockSize; i++)
    {
        oKeyPad[i] ^= key[i];
        iKeyPad[i] ^= key[i];
    }

    free(key);

    memcpy(buf1, iKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf1 + hmacHashFunctionEx.blockSize, inputMessage, inputMessageSize);
    
    buf1Hash = HashFunctions::getHash(buf1, buf1Size, hashFunctionName);

    free(iKeyPad);
    free(buf1);

    memcpy(buf2, oKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf2 + hmacHashFunctionEx.blockSize, buf1Hash, hmacHashFunctionEx.hashSize);
    
    free(oKeyPad);
    free(buf1Hash);
    
    hash = HashFunctions::getHash(buf2, buf2Size, hashFunctionName);

    free(buf2);

    return hash;
}

unsigned char* HMAC::getHMAC(string keyHex, unsigned char *message, size_t messageLength, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction)
{
    unsigned char *inputKey;
    size_t inputKeySize;
    unsigned char *key;
    size_t keySize;
    unsigned char *hash;
    unsigned char *oKeyPad;
    unsigned char *iKeyPad;
    
    unsigned char *buf1;
    size_t buf1Size;

    unsigned char *buf2;
    size_t buf2Size;
    
    unsigned char *buf1Hash;
    
    HMAC::HMACHashFunctionEx hmacHashFunctionEx = getHMACHashFunctionEx(hmacHashFunction);
    string hashFunctionName = hmacHashFunctionEx.name;
    stringToLowercase(hashFunctionName);

    inputKeySize = keyHex.length() / 2;
    //inputKey = (unsigned char *)malloc(inputKeySize * sizeof(unsigned char));
    inputKey = hexToByteArray(keyHex.c_str());
    
    keySize = hmacHashFunctionEx.blockSize;
    key = (unsigned char *)malloc(keySize * sizeof(unsigned char));
    hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));
    oKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));
    iKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));

    buf1Size = hmacHashFunctionEx.blockSize + messageLength;
    buf2Size = hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize;

    buf1 = (unsigned char *)malloc(buf1Size * sizeof(unsigned char));
    buf2 = (unsigned char *)malloc(buf2Size * sizeof(unsigned char));

    buf1Hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));

    memset(key, 0x00, hmacHashFunctionEx.blockSize);
    memset(oKeyPad, 0x5c, hmacHashFunctionEx.blockSize);
    memset(iKeyPad, 0x36, hmacHashFunctionEx.blockSize);
    memset(buf1, 0x00, hmacHashFunctionEx.blockSize + messageLength);
    memset(buf2, 0x00, hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize);

    if (inputKeySize > hmacHashFunctionEx.blockSize)
    {
        key = HashFunctions::getHash(inputKey, inputKeySize, hashFunctionName);
    }
    else
    {
        memcpy(key, inputKey, inputKeySize);
    }

    free(inputKey);

    for (int i = 0; i < hmacHashFunctionEx.blockSize; i++)
    {
        oKeyPad[i] ^= key[i];
        iKeyPad[i] ^= key[i];
    }

    free(key);

    memcpy(buf1, iKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf1 + hmacHashFunctionEx.blockSize, message, messageLength);
    
    buf1Hash = HashFunctions::getHash(buf1, buf1Size, hashFunctionName);

    free(iKeyPad);
    free(buf1);

    memcpy(buf2, oKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf2 + hmacHashFunctionEx.blockSize, buf1Hash, hmacHashFunctionEx.hashSize);
    
    free(oKeyPad);
    free(buf1Hash);
    
    hash = HashFunctions::getHash(buf2, buf2Size, hashFunctionName);

    free(buf2);

    return hash;
}

char* HMAC::getHMACHex(string keyHex, string message, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction)
{
    unsigned char *inputMessage;
    size_t inputMessageSize;
    unsigned char *inputKey;
    size_t inputKeySize;
    unsigned char *key;
    size_t keySize;
    unsigned char *hash;
    char *hashHex;
    unsigned char *oKeyPad;
    unsigned char *iKeyPad;
    
    unsigned char *buf1;
    size_t buf1Size;

    unsigned char *buf2;
    size_t buf2Size;
    
    unsigned char *buf1Hash;
    
    HMAC::HMACHashFunctionEx hmacHashFunctionEx = getHMACHashFunctionEx(hmacHashFunction);
    string hashFunctionName = hmacHashFunctionEx.name;
    stringToLowercase(hashFunctionName);

    inputMessageSize = message.length();
    inputMessage = (unsigned char *)malloc(inputMessageSize * sizeof(unsigned char));
    std::copy(message.cbegin(), message.cend(), inputMessage);

    inputKeySize = keyHex.length() / 2;
    //inputKey = (unsigned char *)malloc(inputKeySize * sizeof(unsigned char));
    inputKey = hexToByteArray(keyHex.c_str());
    
    keySize = hmacHashFunctionEx.blockSize;
    key = (unsigned char *)malloc(keySize * sizeof(unsigned char));
    hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));
    oKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));
    iKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));

    buf1Size = hmacHashFunctionEx.blockSize + inputMessageSize;
    buf2Size = hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize;

    buf1 = (unsigned char *)malloc(buf1Size * sizeof(unsigned char));
    buf2 = (unsigned char *)malloc(buf2Size * sizeof(unsigned char));

    buf1Hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));

    memset(key, 0x00, hmacHashFunctionEx.blockSize);
    memset(oKeyPad, 0x5c, hmacHashFunctionEx.blockSize);
    memset(iKeyPad, 0x36, hmacHashFunctionEx.blockSize);
    memset(buf1, 0x00, hmacHashFunctionEx.blockSize + inputMessageSize);
    memset(buf2, 0x00, hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize);

    if (inputKeySize > hmacHashFunctionEx.blockSize)
    {
        key = HashFunctions::getHash(inputKey, inputKeySize, hashFunctionName);
    }
    else
    {
        memcpy(key, inputKey, inputKeySize);
    }

    free(inputKey);

    for (int i = 0; i < hmacHashFunctionEx.blockSize; i++)
    {
        oKeyPad[i] ^= key[i];
        iKeyPad[i] ^= key[i];
    }

    free(key);

    memcpy(buf1, iKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf1 + hmacHashFunctionEx.blockSize, inputMessage, inputMessageSize);
    
    buf1Hash = HashFunctions::getHash(buf1, buf1Size, hashFunctionName);
    
    free(iKeyPad);
    free(buf1);

    memcpy(buf2, oKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf2 + hmacHashFunctionEx.blockSize, buf1Hash, hmacHashFunctionEx.hashSize);
    
    free(oKeyPad);
    free(buf1Hash);
    
    hash = HashFunctions::getHash(buf2, buf2Size, hashFunctionName);

    free(buf2);

    hashHex = byteArrayToHex(hash, hmacHashFunctionEx.hashSize);
    free(hash);

    return hashHex;
}

char* HMAC::getHMACHex(string keyHex, unsigned char *message, size_t messageLength, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction)
{
    unsigned char *inputKey;
    size_t inputKeySize;
    unsigned char *key;
    size_t keySize;
    unsigned char *hash;
    char *hashHex;
    unsigned char *oKeyPad;
    unsigned char *iKeyPad;
    
    unsigned char *buf1;
    size_t buf1Size;

    unsigned char *buf2;
    size_t buf2Size;
    
    unsigned char *buf1Hash;
    
    HMAC::HMACHashFunctionEx hmacHashFunctionEx = getHMACHashFunctionEx(hmacHashFunction);
    string hashFunctionName = hmacHashFunctionEx.name;
    stringToLowercase(hashFunctionName);

    inputKeySize = keyHex.length() / 2;
    //inputKey = (unsigned char *)malloc(inputKeySize * sizeof(unsigned char));
    inputKey = hexToByteArray(keyHex.c_str());
    
    keySize = hmacHashFunctionEx.blockSize;
    key = (unsigned char *)malloc(keySize * sizeof(unsigned char));
    hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));
    oKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));
    iKeyPad = (unsigned char *)malloc(hmacHashFunctionEx.blockSize * sizeof(unsigned char));

    buf1Size = hmacHashFunctionEx.blockSize + messageLength;
    buf2Size = hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize;

    buf1 = (unsigned char *)malloc(buf1Size * sizeof(unsigned char));
    buf2 = (unsigned char *)malloc(buf2Size * sizeof(unsigned char));

    buf1Hash = (unsigned char *)malloc(hmacHashFunctionEx.hashSize * sizeof(unsigned char));

    memset(key, 0x00, hmacHashFunctionEx.blockSize);
    memset(oKeyPad, 0x5c, hmacHashFunctionEx.blockSize);
    memset(iKeyPad, 0x36, hmacHashFunctionEx.blockSize);
    memset(buf1, 0x00, hmacHashFunctionEx.blockSize + messageLength);
    memset(buf2, 0x00, hmacHashFunctionEx.blockSize + hmacHashFunctionEx.hashSize);

    if (inputKeySize > hmacHashFunctionEx.blockSize)
    {
        key = HashFunctions::getHash(inputKey, inputKeySize, hashFunctionName);
    }
    else
    {
        memcpy(key, inputKey, inputKeySize);
    }

    free(inputKey);

    for (int i = 0; i < hmacHashFunctionEx.blockSize; i++)
    {
        oKeyPad[i] ^= key[i];
        iKeyPad[i] ^= key[i];
    }

    free(key);

    memcpy(buf1, iKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf1 + hmacHashFunctionEx.blockSize, message, messageLength);
    
    buf1Hash = HashFunctions::getHash(buf1, buf1Size, hashFunctionName);

    free(iKeyPad);
    free(buf1);

    memcpy(buf2, oKeyPad, hmacHashFunctionEx.blockSize);
    memcpy(buf2 + hmacHashFunctionEx.blockSize, buf1Hash, hmacHashFunctionEx.hashSize);
    
    free(oKeyPad);
    free(buf1Hash);
    
    hash = HashFunctions::getHash(buf2, buf2Size, hashFunctionName);

    free(buf2);

    hashHex = byteArrayToHex(hash, hmacHashFunctionEx.hashSize);
    free(hash);

    return hashHex;
}
