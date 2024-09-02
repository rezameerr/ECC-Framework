#include "../../include/ECC/ECIESCryptographySuits.h"

ECIESCryptographySuits::ECIESCryptographySuits()
{
}

ECIESCryptographySuits::~ECIESCryptographySuits()
{
}

ECIESCryptographySuits::ECIESCryptographySuitEx ECIESCryptographySuits::getECIESCryptographySuitEx(ECIES_CRYPTOGRAPHY_SUIT ECIESCryptographySuit)
{
    ECIESCryptographySuits::ECIESCryptographySuitEx eciesCryptographySuitEx;

    switch (ECIESCryptographySuit)
    {
    case ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC:
        eciesCryptographySuitEx.eciesCryptographySuit = ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC;
        eciesCryptographySuitEx.name = "Argon2id_HMACBLAKE2b_Twofish-256-CBC";
        eciesCryptographySuitEx.keyDerivationFunction = "Argon2id";
        eciesCryptographySuitEx.mac = HMAC::HMAC_HASH_FUNCTIONS::BLAKE2b;
        eciesCryptographySuitEx.macName = "HMAC-BLAKE2b";
        eciesCryptographySuitEx.macSize = HMAC::getHMACHashFunctionEx(eciesCryptographySuitEx.mac).hashSize;
        eciesCryptographySuitEx.symmetricEncryptionScheme = "Twofish-256-CBC";
        eciesCryptographySuitEx.symmetricEncryptionKeySize = 32;
        eciesCryptographySuitEx.symmetricEncryptionBlockSize = 16;
        eciesCryptographySuitEx.symmetricEncryptionModeIVSize = 16;
        eciesCryptographySuitEx.hashFunctionName = "BLAKE2b";
        eciesCryptographySuitEx.hashSize = HMAC::getHMACHashFunctionEx(eciesCryptographySuitEx.mac).hashSize;
        break;
    
    default:
        eciesCryptographySuitEx.eciesCryptographySuit = ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC;
        eciesCryptographySuitEx.name = "Argon2id_HMACBLAKE2b_Twofish-256-CBC";
        eciesCryptographySuitEx.keyDerivationFunction = "Argon2id";
        eciesCryptographySuitEx.mac = HMAC::HMAC_HASH_FUNCTIONS::BLAKE2b;
        eciesCryptographySuitEx.macName = "HMAC-BLAKE2b";
        eciesCryptographySuitEx.macSize = HMAC::getHMACHashFunctionEx(eciesCryptographySuitEx.mac).hashSize;
        eciesCryptographySuitEx.symmetricEncryptionScheme = "Twofish-256-CBC";
        eciesCryptographySuitEx.symmetricEncryptionKeySize = 32;
        eciesCryptographySuitEx.symmetricEncryptionBlockSize = 16;
        eciesCryptographySuitEx.symmetricEncryptionModeIVSize = 16;
        eciesCryptographySuitEx.hashFunctionName = "BLAKE2b";
        eciesCryptographySuitEx.hashSize = HMAC::getHMACHashFunctionEx(eciesCryptographySuitEx.mac).hashSize;
        break;
    }

    return eciesCryptographySuitEx;
}