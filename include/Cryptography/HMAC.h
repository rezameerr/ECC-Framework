#ifndef __HMAC_H__
#define __HMAC_H__

#include "../Utils/Common.h"
#include "../Cryptography/HashFunctions.h"

class HMAC
{
private:

public:
    enum HMAC_HASH_FUNCTIONS
    {
        BLAKE2b = 1,
        BLAKE2b_256,
        SHA3_512,
        SHA3_256,
        SHA_512,
        SHA_384,
        SHA_256,
        //SHA1, // Insecure - Not Recommended
        //MD5, // Insecure - Not Recommended
    };

    struct HMACHashFunctionEx
    {
        HMAC_HASH_FUNCTIONS hmacHashFunction;
        string name;
        uint32_t blockSize;
        uint32_t hashSize;
    };

    HMAC();
    ~HMAC();

    static HMACHashFunctionEx getHMACHashFunctionEx(HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction);
    static unsigned char* getHMAC(string keyHex, string message, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction);
    static unsigned char* getHMAC(string keyHex, unsigned char *message, size_t messageLength, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction);
    static char* getHMACHex(string keyHex, string message, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction);
    static char* getHMACHex(string keyHex, unsigned char *message, size_t messageLength, HMAC::HMAC_HASH_FUNCTIONS hmacHashFunction);
};

#endif // __HMAC_H__