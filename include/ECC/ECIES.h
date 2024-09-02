#ifndef __ECIES_H__
#define __ECIES_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "../Math/EllipticCurveFq.h"
#include "ECCDomainParameters.h"
#include "ECC.h"
#include "ECCKey.h"
#include "ECCPrivateKey.h"
#include "ECCPublicKey.h"
#include "ECIESCryptographySuits.h"
#include "ECDSA.h"
#include "StandardCurves.h"
#include "../../src/Cryptography/argon2/include/argon2.h"

class ECIES
{
private:
    ECC ecc;
    ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E;
    ECIESCryptographySuits::ECIESCryptographySuitEx EEx;
    string symmetricEncryptionModeIV;
    string salt;
    ECCKey eccKey;
    ECCPrivateKey eccPrivateKey;
    ECCPublicKey eccPublicKey;
    string sharedSecretKey;
    string macKey;
    string s1;
    string s2;

public:
    struct ECIESEncryptedBlock
    {
        ECIESCryptographySuits::ECIESCryptographySuitEx EEx;
        ECCPublicKey publicKey;
        unsigned char* ciphertext;
        char* ciphertextHex;
        uint64_t ciphertextSize;
        unsigned char* mac;
        char* macHex;        
    };

    ECIES(ECC ecc);
    ECIES(string standardCurveName);
    ECIES(ECCDomainParameters eccDomainParams);
    ECIES(ECC ecc, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E);
    ECIES(string standardCurveName, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E);
    ECIES(ECCDomainParameters eccDomainParams, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E);
    ECIES(string standardCurveName, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E, string symmetricEncryptionModeIV, string salt, string s1, string s2);
    ECIES(ECC ecc, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E, string symmetricEncryptionModeIV, string salt, string s1, string s2);
    ECIES(ECCDomainParameters eccDomainParams, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E, string symmetricEncryptionModeIV, string salt, string s1, string s2);
    ~ECIES();

    ECC getECC();
    ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT getE();
    ECIESCryptographySuits::ECIESCryptographySuitEx getEEx();
    string getSymmetricEncryptionModeIV();
    string getSalt();
    ECCKey getECCKey();
    ECCPrivateKey getPrivateKey();
    ECCPublicKey getPublicKey();
    string getSharedSecretKey();
    string getS1();
    void setS1(string s1);
    string getS2();
    void setS2(string s2);

    void setKeyPair(ECCKey eccKey);
    void setKeyPair(ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);
    void setKeyPair(Integer d, ECPoint Q);
    void generateKeyPair();
    void generateSharedSecretKey(ECPoint Q);
    void generateSharedSecretKey(ECCPublicKey publicKey);
    ECDSA::ECDSASignature sign(const string message);
    ECDSA::ECDSASignature sign(ECCPrivateKey eccPrivateKey, const string message);
    ECDSA::ECDSASignature sign(Integer d, const string message);
    bool verify(const string message, ECDSA::ECDSASignature ecdsaSignature);
    bool verify(ECCPublicKey eccPublicKey, const string message, ECDSA::ECDSASignature ecdsaSignature);
    bool verify(ECPoint Q, const string message, ECDSA::ECDSASignature ecdsaSignature);
    unsigned char* encrypt(string message, uint64_t *ciphertextLength);
    unsigned char* encrypt(unsigned char *message, uint64_t messageLength, uint64_t *ciphertextLength);
    char* encryptHex(string message, uint64_t *ciphertextHexLength);
    char* encryptHex(unsigned char *message, uint64_t messageLength, uint64_t *ciphertextHexLength);
    unsigned char* decrypt(unsigned char *encryptedMessage, uint64_t encryptedMessageLength, uint64_t *decryptedMessageLength);
    unsigned char* decryptHex(char *encryptedMessage, uint64_t *decryptedMessageLength);
    unsigned char* getMAC(string message);
    unsigned char* getMAC(unsigned char *message, uint64_t messageLength);
    char* getMACHex(string message);
    char* getMACHex(unsigned char *message, uint64_t messageLength);
    bool verifyMAC(string message, unsigned char* mac);
    bool verifyMAC(unsigned char *message, uint64_t messageLength, unsigned char* mac);
    bool verifyMACHex(string message, char* mac);
    bool verifyMACHex(unsigned char *message, uint64_t messageLength, char* mac);
    ECIESEncryptedBlock fullEncryption(string message);
    ECIESEncryptedBlock fullEncryption(unsigned char *message, uint64_t messageLength);
    unsigned char* fullDecryption(ECIES::ECIESEncryptedBlock eciesEncryptedBlock, uint64_t *decryptedMessageSize);
    
    ECIES operator=(const ECIES& e);
};

#endif // __ECIES_H__