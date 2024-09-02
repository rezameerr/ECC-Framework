#ifndef __ECIESCRYPTOGRAPHYSUITS_H__
#define __ECIESCRYPTOGRAPHYSUITS_H__

#include "../Utils/Common.h"
#include "../../include/Cryptography/HMAC.h"

class ECIESCryptographySuits
{
private:

public:
    enum ECIES_CRYPTOGRAPHY_SUIT
    {
        // KFD_MAC_SYMMETRICENCRYPTIONSCHEME
        ARGON2ID_HMACBLAKE2B_TWOFISH256CBC = 1,
        ARGON2ID_KEYEDBLAKE2B_TWOFISH256CBC,
        ARGON2ID_HMACBLAKE2B256_TWOFISH256CBC,
        SCRYPT_HMACBLAKE2B256_TWOFISH256CBC,
        ARGON2ID_HMACBLAKE2B256_AES256,
        SCRYPT_HMACBLAKE2B256_AES256,
        ARGON2ID_HMACSHA3256_TWOFISH256CBC,
        SCRYPT_HMACSHA3256_TWOFISH256CBC,
        ARGON2ID_HMACSHA3256_AES256,
        SCRYPT_HMACSHA3256_AES256,
        ARGON2ID_HMACSHA256_TWOFISH256CBC,
        SCRYPT_HMACSHA256_TWOFISH256CBC,
        ARGON2ID_HMACSHA256_AES256,
        SCRYPT_HMACSHA256_AES256,
    };

    struct ECIESCryptographySuitEx
    {
        ECIES_CRYPTOGRAPHY_SUIT eciesCryptographySuit;
        string name;
        string keyDerivationFunction;
        HMAC::HMAC_HASH_FUNCTIONS mac;
        string macName;
        uint32_t macSize;
        string symmetricEncryptionScheme;
        uint32_t symmetricEncryptionKeySize;
        uint32_t symmetricEncryptionBlockSize;
        uint32_t symmetricEncryptionModeIVSize;
        string hashFunctionName;
        uint32_t hashSize;
    };

    ECIESCryptographySuits();
    ~ECIESCryptographySuits();

    static ECIESCryptographySuitEx getECIESCryptographySuitEx(ECIES_CRYPTOGRAPHY_SUIT ECIESCryptographySuit);
};

#endif // __ECIESCRYPTOGRAPHYSUITS_H__