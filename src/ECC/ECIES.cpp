#include "../../include/ECC/ECIES.h"
#include "../../include/ECC/ECDHE.h"
#include "../../include/Cryptography/TwofishWrapper.h"
#include "../../include/Cryptography/HMAC.h"

ECIES::ECIES(ECC ecc)
{
    this->ecc = ecc;
    E = ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(E);
    symmetricEncryptionModeIV = secureRandomUsingOpenSSLHex(EEx.symmetricEncryptionModeIVSize);
    salt = secureRandomUsingOpenSSLBase64(EEx.symmetricEncryptionKeySize);
    this->s1 = "";
    this->s2 = "";
}

ECIES::ECIES(string standardCurveName)
{
    ecc.setDomainParams(*StandardCurves::getECCDomainParametersByStandardCurveName(standardCurveName));
    E = ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(E);
    symmetricEncryptionModeIV = secureRandomUsingOpenSSLHex(EEx.symmetricEncryptionModeIVSize);
    salt = secureRandomUsingOpenSSLBase64(EEx.symmetricEncryptionKeySize);
    this->s1 = "";
    this->s2 = "";
}

ECIES::ECIES(ECCDomainParameters eccDomainParams)
{
    ecc.setDomainParams(eccDomainParams);
    E = ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(E);
    symmetricEncryptionModeIV = secureRandomUsingOpenSSLHex(EEx.symmetricEncryptionModeIVSize);
    salt = secureRandomUsingOpenSSLBase64(EEx.symmetricEncryptionKeySize);
    this->s1 = "";
    this->s2 = "";
}

ECIES::ECIES(ECC ecc, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E)
{
    this->ecc = ecc;
    this->E = E;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(E);
    symmetricEncryptionModeIV = secureRandomUsingOpenSSLHex(EEx.symmetricEncryptionModeIVSize);
    salt = secureRandomUsingOpenSSLBase64(EEx.symmetricEncryptionKeySize);
    this->s1 = "";
    this->s2 = "";
}

ECIES::ECIES(string standardCurveName, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E)
{
    ecc.setDomainParams(*StandardCurves::getECCDomainParametersByStandardCurveName(standardCurveName));
    this->E = E;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(E);
    symmetricEncryptionModeIV = secureRandomUsingOpenSSLHex(EEx.symmetricEncryptionModeIVSize);
    salt = secureRandomUsingOpenSSLBase64(EEx.symmetricEncryptionKeySize);
    this->s1 = "";
    this->s2 = "";
}

ECIES::ECIES(ECCDomainParameters eccDomainParams, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E)
{
    ecc.setDomainParams(eccDomainParams);
    this->E = E;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(E);
    symmetricEncryptionModeIV = secureRandomUsingOpenSSLHex(EEx.symmetricEncryptionModeIVSize);
    salt = secureRandomUsingOpenSSLBase64(EEx.symmetricEncryptionKeySize);
    this->s1 = "";
    this->s2 = "";
}

ECIES::ECIES(ECC ecc, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E, string symmetricEncryptionModeIV, string salt, string s1, string s2)
{
    this->ecc = ecc;
    this->E = E;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(this->E);
    this->symmetricEncryptionModeIV = symmetricEncryptionModeIV;
    this->salt = salt;
    this->s1 = s1;
    this->s2 = s2;
}

ECIES::ECIES(string standardCurveName, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E, string symmetricEncryptionModeIV, string salt, string s1, string s2)
{
    ecc.setDomainParams(*StandardCurves::getECCDomainParametersByStandardCurveName(standardCurveName));
    this->E = E;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(this->E);
    this->symmetricEncryptionModeIV = symmetricEncryptionModeIV;
    this->salt = salt;
    this->s1 = s1;
    this->s2 = s2;
}

ECIES::ECIES(ECCDomainParameters eccDomainParams, ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT E, string symmetricEncryptionModeIV, string salt, string s1, string s2)
{
    ecc.setDomainParams(eccDomainParams);
    this->E = E;
    EEx = ECIESCryptographySuits::getECIESCryptographySuitEx(this->E);
    this->symmetricEncryptionModeIV = symmetricEncryptionModeIV;
    this->salt = salt;
    this->s1 = s1;
    this->s2 = s2;
}

ECIES::~ECIES()
{
}

ECC ECIES::getECC()
{
    return ecc;
}

ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT ECIES::getE()
{
    return E;
}

ECIESCryptographySuits::ECIESCryptographySuitEx ECIES::getEEx()
{
    return EEx;
}

string ECIES::getSymmetricEncryptionModeIV()
{
    return symmetricEncryptionModeIV;
}

string ECIES::getSalt()
{
    return salt;
}

ECCKey ECIES::getECCKey()
{
    return eccKey;
}

ECCPrivateKey ECIES::getPrivateKey()
{
    return eccPrivateKey;
}

ECCPublicKey ECIES::getPublicKey()
{
    return eccPublicKey;
}

string ECIES::getSharedSecretKey()
{
    return sharedSecretKey;
}

string ECIES::getS1()
{
    return s1;
}

void ECIES::setS1(string s1)
{
    this->s1 = s1;
}

string ECIES::getS2()
{
    return s2;
}

void ECIES::setS2(string s2)
{
    this->s2 = s2;
}

void ECIES::setKeyPair(ECCKey eccKey)
{
    this->eccKey = eccKey;
    eccPrivateKey.d = eccKey.getd();
    eccPublicKey.Q = eccKey.getQ();
    eccPublicKey.setDomainParams(ecc.getDomainParams());
}

void ECIES::setKeyPair(ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    this->eccKey.setdQ(eccPrivateKey.d, eccPublicKey.Q);
    eccPrivateKey.d = eccPrivateKey.d;
    eccPublicKey.Q = eccPublicKey.Q;
    eccPublicKey.setDomainParams(ecc.getDomainParams());
}

void ECIES::setKeyPair(Integer d, ECPoint Q)
{
    this->eccKey.setdQ(d, Q);
    eccPrivateKey.d = d;
    eccPublicKey.Q = Q;
    eccPublicKey.setDomainParams(ecc.getDomainParams());
}

void ECIES::generateKeyPair()
{
    eccKey = ecc.generateKeyPair();
    eccPrivateKey.d = eccKey.getd();
    eccPublicKey.Q = eccKey.getQ();
    eccPublicKey.setDomainParams(ecc.getDomainParams());
}

void ECIES::generateSharedSecretKey(ECPoint Q)
{
    unsigned char *hash;
    const char *saltCharArray = salt.c_str();

    hash = (unsigned char*)malloc(EEx.symmetricEncryptionKeySize * sizeof(unsigned char));
    
    string sharedSecretKeyRaw = ECDHE::generateSharedSecretKey(ecc, eccKey, Q);
    // concat S1
    sharedSecretKeyRaw += s1;

    const char *sharedSecretKeyCharArray = sharedSecretKeyRaw.c_str();
    
    if (EEx.keyDerivationFunction == "Argon2id")
    {
        // Argon2id parameteres
        int argon2idVersion = ARGON2_VERSION_13;
        
        uint32_t t = 100;
        uint32_t m = 100000;
        uint32_t p = 10;
        
        /*
        uint32_t t = 1;
        uint32_t m = 100;
        uint32_t p = 1;
        */    

        argon2_hash(t, m, p, sharedSecretKeyCharArray, strlen(sharedSecretKeyCharArray), 
            saltCharArray, strlen(saltCharArray), hash, EEx.symmetricEncryptionKeySize, 
            NULL, 0, Argon2_id, argon2idVersion);
        
        sharedSecretKey = byteArrayToHex(hash, EEx.symmetricEncryptionKeySize);
        macKey = sharedSecretKey; // TO-DO: different mac
    }

    free(hash);
}

void ECIES::generateSharedSecretKey(ECCPublicKey publicKey)
{
    ECIES::generateSharedSecretKey(publicKey.Q);
}

ECDSA::ECDSASignature ECIES::sign(const string message)
{
    ECDSA::ECDSASignature ecdsaSignature = ECDSA::sign(ecc, eccKey, EEx.hashFunctionName, message);

    return ecdsaSignature;
}

ECDSA::ECDSASignature ECIES::sign(ECCPrivateKey eccPrivateKey, const string message)
{
    ECDSA::ECDSASignature ecdsaSignature = ECDSA::sign(ecc, eccPrivateKey, EEx.hashFunctionName, message);

    return ecdsaSignature;
}

ECDSA::ECDSASignature ECIES::sign(Integer d, const string message)
{
    ECDSA::ECDSASignature ecdsaSignature = ECDSA::sign(ecc, d, EEx.hashFunctionName, message);

    return ecdsaSignature;
}

bool ECIES::verify(const string message, ECDSA::ECDSASignature ecdsaSignature)
{
    return ECDSA::verify(ecc, eccKey.getQ(), EEx.hashFunctionName, message, ecdsaSignature);
}

bool ECIES::verify(ECCPublicKey eccPublicKey, const string message, ECDSA::ECDSASignature ecdsaSignature)
{
    return ECDSA::verify(ecc, eccPublicKey, EEx.hashFunctionName, message, ecdsaSignature);
}

bool ECIES::verify(ECPoint Q, const string message, ECDSA::ECDSASignature ecdsaSignature)
{
    return ECDSA::verify(ecc, Q, EEx.hashFunctionName, message, ecdsaSignature);
}

unsigned char* ECIES::encrypt(string message, uint64_t *ciphertextLength)
{
    unsigned char *messageCharArray;
    unsigned char *output;
    
    //string symmetricEncryptionSchemeLowercase = EEx.symmetricEncryptionScheme;
    //stringToLowercase(symmetricEncryptionSchemeLowercase);
    
    messageCharArray = (unsigned char *)malloc(message.length() * sizeof(unsigned char));
    std::copy(message.cbegin(), message.cend(), messageCharArray);

    if (EEx.symmetricEncryptionScheme == "Twofish-256-CBC")
    {
        output = twofishEncrypt_256_CBC_PKCS7(sharedSecretKey.c_str(), symmetricEncryptionModeIV.c_str(), messageCharArray, message.length(), ciphertextLength);

        free(messageCharArray);

        return output;
    }

    return NULL;
}

unsigned char* ECIES::encrypt(unsigned char *message, uint64_t messageLength, uint64_t *ciphertextLength)
{
    //string symmetricEncryptionSchemeLowercase = EEx.symmetricEncryptionScheme;
    //stringToLowercase(symmetricEncryptionSchemeLowercase);

    if (EEx.symmetricEncryptionScheme == "Twofish-256-CBC")
    {
        return twofishEncrypt_256_CBC_PKCS7(sharedSecretKey.c_str(), symmetricEncryptionModeIV.c_str(), message, messageLength, ciphertextLength);
    }

    return NULL;
}

char* ECIES::encryptHex(string message, uint64_t *ciphertextHexLength)
{
    unsigned char *messageCharArray;
    char *output;
    
    //string symmetricEncryptionSchemeLowercase = EEx.symmetricEncryptionScheme;
    //stringToLowercase(symmetricEncryptionSchemeLowercase);

    messageCharArray = (unsigned char *)malloc(message.length() * sizeof(unsigned char));
    std::copy(message.cbegin(), message.cend(), messageCharArray);

    if (EEx.symmetricEncryptionScheme == "Twofish-256-CBC")
    {
        output = twofishEncrypt_256_CBC_PKCS7_Hex(sharedSecretKey.c_str(), symmetricEncryptionModeIV.c_str(), messageCharArray, message.length(), ciphertextHexLength);
        
        free(messageCharArray);

        return output;

    }

    return NULL;
}

char* ECIES::encryptHex(unsigned char *message, uint64_t messageLength, uint64_t *ciphertextHexLength)
{
    //string symmetricEncryptionSchemeLowercase = EEx.symmetricEncryptionScheme;
    //stringToLowercase(symmetricEncryptionSchemeLowercase);

    if (EEx.symmetricEncryptionScheme == "Twofish-256-CBC")
    {
        return twofishEncrypt_256_CBC_PKCS7_Hex(sharedSecretKey.c_str(), symmetricEncryptionModeIV.c_str(), message, messageLength, ciphertextHexLength);
    }

    return NULL;
}

unsigned char* ECIES::decrypt(unsigned char *encryptedMessage, uint64_t encryptedMessageLength, uint64_t *decryptedMessageLength)
{
    //string symmetricEncryptionSchemeLowercase = EEx.symmetricEncryptionScheme;
    //stringToLowercase(symmetricEncryptionSchemeLowercase);

    if (EEx.symmetricEncryptionScheme == "Twofish-256-CBC")
    {
        return twofishDecrypt_256_CBC_PKCS7(sharedSecretKey.c_str(), symmetricEncryptionModeIV.c_str(), encryptedMessage, encryptedMessageLength, decryptedMessageLength);
    }

    return NULL;
}

unsigned char* ECIES::decryptHex(char *encryptedMessage, uint64_t *decryptedMessageLength)
{
    //string symmetricEncryptionSchemeLowercase = EEx.symmetricEncryptionScheme;
    //stringToLowercase(symmetricEncryptionSchemeLowercase);

    if (EEx.symmetricEncryptionScheme == "Twofish-256-CBC")
    {
        return twofishDecrypt_256_CBC_PKCS7_Hex(sharedSecretKey.c_str(), symmetricEncryptionModeIV.c_str(), encryptedMessage, decryptedMessageLength);
    }

    return NULL;
}

unsigned char* ECIES::getMAC(string message)
{
    return HMAC::getHMAC(macKey, message, EEx.mac);
}

unsigned char* ECIES::getMAC(unsigned char *message, uint64_t messageLength)
{
    return HMAC::getHMAC(macKey, message, messageLength, EEx.mac);
}

char* ECIES::getMACHex(string message)
{
    return HMAC::getHMACHex(macKey, message, EEx.mac);
}

char* ECIES::getMACHex(unsigned char *message, uint64_t messageLength)
{
    return HMAC::getHMACHex(macKey, message, messageLength, EEx.mac);
}

bool ECIES::verifyMAC(string message, unsigned char* mac)
{
    unsigned char *computedHMAC = HMAC::getHMAC(macKey, message, EEx.mac);

    if (memcmp(computedHMAC, mac, EEx.macSize) == 0)
    {
        free(computedHMAC);

        return true;
    }

    free(computedHMAC);

    return false;
}

bool ECIES::verifyMAC(unsigned char *message, uint64_t messageLength, unsigned char* mac)
{
    unsigned char *computedHMAC = HMAC::getHMAC(macKey, message, messageLength, EEx.mac);

    if (memcmp(computedHMAC, mac, EEx.macSize) == 0)
    {
        free(computedHMAC);

        return true;
    }

    free(computedHMAC);
    
    return false;
}

bool ECIES::verifyMACHex(string message, char* mac)
{
    char *computedHMAC = HMAC::getHMACHex(macKey, message, EEx.mac);

    if (memcmp(computedHMAC, mac, EEx.macSize) == 0)
    {
        free(computedHMAC);

        return true;
    }

    free(computedHMAC);
    
    return false;
}

bool ECIES::verifyMACHex(unsigned char *message, uint64_t messageLength, char* mac)
{
    char *computedHMAC = HMAC::getHMACHex(macKey, message, messageLength, EEx.mac);

    if (memcmp(computedHMAC, mac, EEx.macSize) == 0)
    {
        free(computedHMAC);

        return true;
    }

    free(computedHMAC);
    
    return false;
}

ECIES::ECIESEncryptedBlock ECIES::fullEncryption(string message)
{
    ECIES::ECIESEncryptedBlock eciesEncryptedBlock;
    unsigned char *ciphertextForMac;
    uint64_t s2Size = 0;
    uint64_t ciphertextSize = 0;
    uint64_t ciphertextForMacSize = 0;

    unsigned char *ciphertext = encrypt(message, &ciphertextSize);
    char *ciphertextHex = byteArrayToHex(ciphertext, ciphertextSize);

    // concat S2
    s2Size = s2.length();

    if (s2Size > 0)
    {
        unsigned char *s2Bytes = (unsigned char *)malloc(s2Size * sizeof(unsigned char));
        std::copy(s2.cbegin(), s2.cend(), s2Bytes);

        ciphertextForMacSize = ciphertextSize + s2Size;
        ciphertextForMac = (unsigned char *)malloc(ciphertextForMacSize * sizeof(unsigned char));

        memcpy(ciphertextForMac, ciphertext, ciphertextSize);
        memcpy(ciphertextForMac + ciphertextSize, s2Bytes, s2Size);

        free(s2Bytes);
    }
    else
    {
        ciphertextForMacSize = ciphertextSize;
        ciphertextForMac = (unsigned char *)malloc(ciphertextForMacSize * sizeof(unsigned char));

        memcpy(ciphertextForMac, ciphertext, ciphertextSize);
    }

    unsigned char *mac = getMAC(ciphertextForMac, ciphertextForMacSize);
    char *macHex = getMACHex(ciphertextForMac, ciphertextForMacSize);

    free(ciphertextForMac);

    eciesEncryptedBlock.EEx = EEx;
    eciesEncryptedBlock.publicKey = eccPublicKey;
    eciesEncryptedBlock.ciphertext = ciphertext;
    eciesEncryptedBlock.ciphertextHex = ciphertextHex;
    eciesEncryptedBlock.ciphertextSize = ciphertextSize;
    eciesEncryptedBlock.mac = mac;
    eciesEncryptedBlock.macHex = macHex;

    return eciesEncryptedBlock;
}

ECIES::ECIESEncryptedBlock ECIES::fullEncryption(unsigned char *message, uint64_t messageLength)
{
    ECIES::ECIESEncryptedBlock eciesEncryptedBlock;
    unsigned char *ciphertextForMac;
    uint64_t s2Size = 0;
    uint64_t ciphertextSize = 0;
    uint64_t ciphertextForMacSize = 0;

    //unsigned char *ciphertext = encrypt(message, messageLength, &ciphertextSize);
    //char *ciphertextHex = byteArrayToHex(ciphertext, ciphertextSize);
    
    char *ciphertextHex = encryptHex(message, messageLength, &ciphertextSize);
    unsigned char *ciphertext = hexToByteArray(ciphertextHex);

    // concat S2
    s2Size = s2.length();

    if (s2Size > 0)
    {
        unsigned char *s2Bytes = (unsigned char *)malloc(s2Size * sizeof(unsigned char));
        std::copy(s2.cbegin(), s2.cend(), s2Bytes);

        ciphertextForMacSize = ciphertextSize + s2Size;
        ciphertextForMac = (unsigned char *)malloc(ciphertextForMacSize * sizeof(unsigned char));

        memcpy(ciphertextForMac, ciphertext, ciphertextSize);
        memcpy(ciphertextForMac + ciphertextSize, s2Bytes, s2Size);

        free(s2Bytes);        
    }
    else
    {
        ciphertextForMacSize = ciphertextSize;
        ciphertextForMac = (unsigned char *)malloc(ciphertextForMacSize * sizeof(unsigned char));

        memcpy(ciphertextForMac, ciphertext, ciphertextSize);
    }

    unsigned char *mac = getMAC(ciphertextForMac, ciphertextForMacSize);
    char *macHex = getMACHex(ciphertextForMac, ciphertextForMacSize);
    
    free(ciphertextForMac);

    eciesEncryptedBlock.EEx = EEx;
    eciesEncryptedBlock.publicKey = eccPublicKey;
    eciesEncryptedBlock.ciphertext = ciphertext;
    eciesEncryptedBlock.ciphertextHex = ciphertextHex;
    eciesEncryptedBlock.ciphertextSize = ciphertextSize;
    eciesEncryptedBlock.mac = mac;
    eciesEncryptedBlock.macHex = macHex;

    return eciesEncryptedBlock;
}

unsigned char* ECIES::fullDecryption(ECIES::ECIESEncryptedBlock eciesEncryptedBlock, uint64_t *decryptedMessageSize)
{
    unsigned char *ciphertextForMac;
    uint64_t s2Size = 0;
    uint64_t ciphertextSize = eciesEncryptedBlock.ciphertextSize;
    uint64_t ciphertextForMacSize = 0;

    // concat S2
    s2Size = s2.length();

    if (s2Size > 0)
    {
        unsigned char *s2Bytes = (unsigned char *)malloc(s2Size * sizeof(unsigned char));
        std::copy(s2.cbegin(), s2.cend(), s2Bytes);

        ciphertextForMacSize = ciphertextSize + s2Size;
        ciphertextForMac = (unsigned char *)malloc(ciphertextForMacSize * sizeof(unsigned char));

        memcpy(ciphertextForMac, eciesEncryptedBlock.ciphertext, ciphertextSize);
        memcpy(ciphertextForMac + ciphertextSize, s2Bytes, s2Size);

        free(s2Bytes);  
    }
    else
    {
        ciphertextForMacSize = ciphertextSize;
        ciphertextForMac = (unsigned char *)malloc(ciphertextForMacSize * sizeof(unsigned char));

        memcpy(ciphertextForMac, eciesEncryptedBlock.ciphertext, ciphertextSize);
    }

    if (verifyMAC(ciphertextForMac, ciphertextForMacSize, eciesEncryptedBlock.mac) == false)
    {
        free(ciphertextForMac);

        cout << "\nECIES INVALID MAC\n";

        return NULL;
    }

    free(ciphertextForMac);
        
    return decrypt(eciesEncryptedBlock.ciphertext, eciesEncryptedBlock.ciphertextSize, decryptedMessageSize);
}
