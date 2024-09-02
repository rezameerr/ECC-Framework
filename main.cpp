#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <stdio.h>
#include "include/Utils/Common.h"
#include "include/Cryptography/HashFunctions.h"
#include "include/Math/ExtensionField.h"
#include "include/Math/ECPoint.h"
#include "include/Math/EllipticCurve.h"
#include "include/Math/EllipticCurveFq.h"
#include "include/ECC/StandardCurves.h"
#include "include/ECC/ECC.h"
#include "include/ECC/ECCDomainParameters.h"
#include "include/ECC/ECCKey.h"
#include "include/ECC/ECDHE.h"
#include "include/ECC/ECDSA.h"
#include "include/Cryptography/Twofish.h"
#include "include/Cryptography/TwofishWrapper.h"
#include "src/Cryptography/argon2/include/argon2.h"
#include "include/ECC/ECIES.h"
#include "include/Cryptography/HMAC.h"
#include "include/ECC/ECElGamal.h"

#define OUT_LEN 32
#define ENCODED_LEN 108

using namespace std;
using namespace Givaro;

void hashtest(uint32_t version, uint32_t t, uint32_t m, uint32_t p, char *pwd,
              char *salt, char *hexref, char *mcfref, argon2_type type)
{
    unsigned char out[OUT_LEN];
    unsigned char hex_out[OUT_LEN * 2 + 4];
    char encoded[ENCODED_LEN];
    int ret, i;

    printf("Hash test: $v=%d t=%d, m=%d, p=%d, pass=%s, salt=%s: ", version,
           t, m, p, pwd, salt);

    //uint32_t mcost = 1 << m;
    uint32_t mcost = m;
    ret = argon2_hash(t, mcost, p, pwd, strlen(pwd), salt, strlen(salt), out,
                      OUT_LEN, encoded, ENCODED_LEN, type, version);
    assert(ret == ARGON2_OK);

    for (i = 0; i < OUT_LEN; ++i)
        sprintf((char *)(hex_out + i * 2), "%02x", out[i]);
    
    cout << endl << "Argon2id Hash: " << byteArrayToHex(out, OUT_LEN) << endl;

    assert(memcmp(hex_out, hexref, OUT_LEN * 2) == 0);

    if (ARGON2_VERSION_NUMBER == version) {
        assert(memcmp(encoded, mcfref, strlen(mcfref)) == 0);
    }

    ret = argon2_verify(encoded, pwd, strlen(pwd), type);
    assert(ret == ARGON2_OK);
    ret = argon2_verify(mcfref, pwd, strlen(pwd), type);
    assert(ret == ARGON2_OK);

    printf("PASS\n");
}

void my_callback(const OBJ_NAME *obj, void *arg)
{
    printf("Digest: %s\n", obj->name);
}

void argon2Test()
{
    int ret;
    unsigned char out[OUT_LEN];
    char const *msg;
    int version;

    version = ARGON2_VERSION_13;
    printf("Test Argon2id version number: %02x\n", version);

    /* Multiple test cases for various input values */
    hashtest(version, 20, 100000, 10, "password", "somesalt",
             "81e6d5bb52b7caf97a3c3d4f0fd7e33e0a4ae934e6d7cae25731c9d24f04a0f1",
             "$argon2id$v=19$m=100000,t=20,p=10$c29tZXNhbHQ$gebVu1K3yvl6PD1PD9fjPgpK6TTm18riVzHJ0k8EoPE", 
             Argon2_id);
}

void twofishTest()
{
    uint64_t length = 0;

    char *c1 = twofishEncrypt_256_CBC_PKCS7_Hex(
        "163928fb9615edf6005afc98d9fdbb3d830b3a286ebef64dd70be848f17bf9cc", 
        "c1f6fd873e14050697c168b3e9da5db2", (unsigned char *)"1234567890123456", strlen("1234567890123456"), &length);

    cout << c1 << endl;

    unsigned char *p1 = twofishDecrypt_256_CBC_PKCS7_Hex(
        "163928fb9615edf6005afc98d9fdbb3d830b3a286ebef64dd70be848f17bf9cc", 
        "c1f6fd873e14050697c168b3e9da5db2", 
        "E6FC25E19D5DAAC3D88A0802304DDAA885361C9EF4DFF238F940D3D9C5EF1391", &length);

    cout << p1;


    uint8_t *inputUInt8;
    inputUInt8 = hexToByteArray("90afe91BB288544F2C32DC239B2635E6");
    unsigned char *inputStr = byteArrayToString(inputUInt8, 16);

    length = 0;
    unsigned char *c2 = twofishEncrypt_256_CBC_PKCS7(
        "d43bb7556EA32E46F2A282B7D45B4e0D57FF739d4DC92C1BD7FC01700CC8216f", 
        "00000000000000000000000000000000", inputStr, strlen((char *)inputStr), &length);

    cout << "\nTest Vector - Encryption: " << c2 << endl;
    cout << "\nTest Vector - Encryption Hex: " << byteArrayToHex(c2, strlen((char *)c2)) << endl;

    uint64_t length2 = 0;
    unsigned char *p2 = twofishDecrypt_256_CBC_PKCS7(
        "D43BB7556EA32e46F2A282B7D45B4E0D57FF739D4dc92C1bd7fc01700CC8216F", 
        "00000000000000000000000000000000", c2, length, &length2);

    cout << "\nTest Vector - Decryption: " << p2;
    cout << "\nTest Vector - Decryption Hex: " << byteArrayToHex(p2, strlen((char *)p2));

    cout << endl;
    
    Twofish_initialise();

    static Twofish_Byte k256[] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };

    static Twofish_Byte p256[] = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
    };

    static Twofish_Byte c256[] = {
        0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
        0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
    };
  
    //Twofish_Byte key[];
    int key_len = 32;
    Twofish_Byte p[16];
    Twofish_Byte c[16];
    Twofish_Byte tmp[16];               /* scratch pad. */
    Twofish_Byte tmp2[32];               /* scratch pad. */
    Twofish_Byte tmp3[32];               /* scratch pad. */
    Twofish_key xkey, xkey2;           /* The expanded key */
  
    string key256Hex = "";

    char *keyHex = "D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F";
    char *ivHex = "4E0DBC01700CD7FC02B7D45BC56E1B17";
    uint8_t *k256fromhex;
    Twofish_Byte iv[16];

    k256fromhex = hexToByteArray(keyHex);
    hexToByteArray(ivHex, iv);
    key256Hex = byteArrayToHexString(k256fromhex, 32);
    cout << "Hex Key = " << key256Hex << endl;
  

    /* Prepare the key */
    Twofish_prepare_key( k256, key_len, &xkey );
    Twofish_prepare_key( k256fromhex, key_len, &xkey2 );
    
    /*
    * We run the test twice to ensure that the xkey structure
    * is not damaged by the first encryption.
    * Those are hideous bugs to find if you get them in an application.
    */
    for(int i=0; i<2; i++ )
    {
        /* Encrypt and test */
        Twofish_encrypt_block( &xkey, p256, tmp );
        if( memcmp( c256, tmp, 16 ) != 0 )
        {
        cout << "Twofish encryption failure\n";
        }
        else
        {
            cout << "Encryption ok\n";
        }

        /* Decrypt and test */
        Twofish_decrypt_block( &xkey2, c256, tmp );
        if( memcmp( p256, tmp, 16 ) != 0 )
        {
        cout << "Twofish encryption failure\n";
        }
        else
        {
            cout << "Decryption ok\n";
        }
    }

    cout << "\n----------------------New hex-------\n";
    for(int i=0; i<2; i++ )
    {
        /* Encrypt and test */
        Twofish_encrypt_block( &xkey2, p256, tmp );
        if( memcmp( c256, tmp, 16 ) != 0 )
        {
        cout << "Twofish encryption failure\n";
        }
        else
        {
            cout << "Encryption ok\n";
        }

        /* Decrypt and test */
        Twofish_decrypt_block( &xkey2, c256, tmp );
        if( memcmp( p256, tmp, 16 ) != 0 )
        {
        cout << "Twofish encryption failure\n";
        }
        else
        {
            cout << "Decryption ok\n";
        }
    }

    Twofish_context context;
    //context.iv = &iv;
    context.options = (Twofish_options)(Twofish_options::Twofish_option_CBC | Twofish_options::Twofish_option_PaddingPKCS7);
    context.key = xkey2;

    //Twofish_prepare_key(k256fromhex, 32, &(context.key));
    memcpy(context.iv, iv, 16);

    //Twofish_encrypt(context, )

    cout << "\n--------context-------\n";
    for(int i=0; i<2; i++ )
    {
        /* Encrypt and test */
        Twofish_encrypt(&context, p256, 16, tmp2, 32);
        for (int j = 0; j < 16; j++)
        {
            tmp3[j] = p256[j] ^ iv[j];
        }
        Twofish_encrypt_block( &xkey2, tmp3, tmp );
        if( memcmp( tmp, tmp2, 16 ) != 0 )
        {
        cout << "Twofish encryption failure\n";
        }
        else
        {
            cout << "Encryption ok\n";
        }

        /* Decrypt and test */
        unsigned long outlen = 32;
        Twofish_decrypt(&context, tmp2, 32, tmp3, &outlen);
        //Twofish_decrypt_block( &xkey2, c256, tmp );
        if( memcmp( p256, tmp3, 16 ) != 0 )
        {
        cout << "Twofish encryption failure\n";
        }
        else
        {
            cout << "Decryption ok\n";
        }
    }
}

void hashAndHMACTest()
{
    /*
    void *my_arg;
    OpenSSL_add_all_digests(); //make sure they're loaded

    my_arg = NULL;
    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, my_callback, my_arg);
    */

    string temp = "The quick brown fox jumps over the lazy dog";
    cout << "SHA256: " << HashFunctions::getHash(temp, "sHa256", "hEX") << endl;
    cout << "MD5: " << HashFunctions::getHash(temp, "md5", "hex") << endl;
    cout << "SHA512: " << HashFunctions::getHash("The quick brown fox jumps over the lazy dog", "sha512", "hex") << endl;
    cout << "SHA3-256: " << HashFunctions::getHash("", "shA3-256", "hex") << endl;
    cout << "BLAKE2b: " << HashFunctions::getHash("", "blake2b", "hex") << endl;
    cout << "BLAKE2b-512: " << HashFunctions::getHash("", "blake2b-512", "hex") << endl;
    cout << "BLAKE2b-256: " << HashFunctions::getHash("", "blake2b-256", "hex") << endl << endl;

    // Test Vectors
    cout << "HMAC-BLAKE2b: " << HMAC::getHMACHex("6B6579", "The quick brown fox jumps over the lazy dog", 
        HMAC::HMAC_HASH_FUNCTIONS::BLAKE2b) << endl << endl;

    cout << "HMAC-BLAKE2b-256: " << HMAC::getHMACHex("6B6579", "The quick brown fox jumps over the lazy dog", 
        HMAC::HMAC_HASH_FUNCTIONS::BLAKE2b_256) << endl << endl;

    cout << "HMAC-SHA-256: " << HMAC::getHMACHex("6B6579", "The quick brown fox jumps over the lazy dog", 
        HMAC::HMAC_HASH_FUNCTIONS::SHA_256) << endl << endl;

    cout << "HMAC-SHA3-256: " << HMAC::getHMACHex("6B6579", "The quick brown fox jumps over the lazy dog", 
        HMAC::HMAC_HASH_FUNCTIONS::SHA3_256) << endl << endl;

    cout << "HMAC-SHA-512: " << HMAC::getHMACHex("6B6579", "The quick brown fox jumps over the lazy dog", 
        HMAC::HMAC_HASH_FUNCTIONS::SHA_512) << endl << endl;

    cout << "HMAC-SHA3-512: " << HMAC::getHMACHex("6B6579", "The quick brown fox jumps over the lazy dog", 
        HMAC::HMAC_HASH_FUNCTIONS::SHA3_512) << endl << endl;

    cout << "HMAC-SHA-512: " << HMAC::getHMACHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 
        "Hi There", 
        HMAC::HMAC_HASH_FUNCTIONS::SHA_512) << endl << endl;
}

void eciesTest()
{
    cout << "\nECIES Test Begins:\n\n";

    ECIES eciesA("secp256k1", 
        ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC);
    
    eciesA.setS1("s1-dummy-abc");
    eciesA.setS2("s2-dummy-xyz");
    
    string ivA = eciesA.getSymmetricEncryptionModeIV();
    string saltA = eciesA.getSalt();
    
    ECIES eciesB("secp256k1", 
        ECIESCryptographySuits::ECIES_CRYPTOGRAPHY_SUIT::ARGON2ID_HMACBLAKE2B_TWOFISH256CBC, 
        ivA, saltA, "s1-dummy-abc", "s2-dummy-xyz");

    ECC eccA = eciesA.getECC();
    ECC eccB = eciesB.getECC();

    cout << "Symmetric Encryption Mode IV A: " << ivA << endl;
    cout << "Salt A: " << saltA << endl;
    cout << "S1 A: " << eciesA.getS1() << endl;
    cout << "S2 A: " << eciesA.getS2() << endl << endl;

    cout << "Symmetric Encryption Mode IV B: " << eciesB.getSymmetricEncryptionModeIV() << endl;
    cout << "Salt B: " << eciesB.getSalt() << endl;
    cout << "S1 B: " << eciesB.getS1() << endl;
    cout << "S2 B: " << eciesB.getS2() << endl << endl;

    eciesA.generateKeyPair();
    cout << "\nKey Pair A: \nPrivate Key A: " << eciesA.getECCKey().getd_InBase(16) << 
        "\nPublic Key A: (" << eciesA.getECCKey().getQ_X_InBase(&eccA, 16) << ", " << 
        eciesA.getECCKey().getQ_Y_InBase(&eccA, 16) << ")" << endl;

    eciesB.generateKeyPair();
    cout << "\nKey Pair B: \nPrivate Key B: " << eciesB.getECCKey().getd_InBase(16) << 
        "\nPublic Key B: (" << eciesB.getECCKey().getQ_X_InBase(&eccB, 16) << ", " << 
        eciesB.getECCKey().getQ_Y_InBase(&eccB, 16) << ")" << endl;

    cout << "\nShared Secret Key Generation... It might take some time, please wait...\n" <<
        "Slow key drivation function - Argon2id @ t=100 & m=100000 & p=10\n";

    eciesA.generateSharedSecretKey(eciesB.getPublicKey());
    cout << "\nShared Secret Key A: " << eciesA.getSharedSecretKey() << endl;

    eciesB.generateSharedSecretKey(eciesA.getPublicKey());
    cout << "\nShared Secret Key B: " << eciesB.getSharedSecretKey() << endl;

    cout << "-------------------\n";
    cout << "Symmetric encryption - A" << endl;
    cout << "-------------------\n";
    unsigned char *plaintextMessage = (unsigned char *)"This is a message from A to B. Hi B, I hope you're doing well. I'm A, can you please help me in programming course?\0";
    uint64_t length = 0;
    char *ciphertextMessage = eciesA.encryptHex(plaintextMessage, strlen((char *)plaintextMessage) + 1, &length);
    unsigned char *ciphertextMessageByteArray = eciesA.encrypt(plaintextMessage, strlen((char *)plaintextMessage) + 1, &length);
    cout << "[Plaintext]: \n" << plaintextMessage << "\n\n[Ciphertext]: \n" << ciphertextMessage << endl << endl;

    cout << "\n-------------------\n";
    cout << "Symmetric decryption - B" << endl;
    cout << "-------------------\n";
    length = 0;
    unsigned char *decryptedMessage = eciesB.decryptHex(ciphertextMessage, &length);
    cout << "[Ciphertext]: \n" << ciphertextMessage << "\n\n[Decrypted]: \n" << decryptedMessage << endl << endl;
    cout << "-------------------\n";

    string messageToSign = "Hello message to sign";

    ECDSA::ECDSASignature ecdsaSignature = eciesA.sign(messageToSign);

    cout << endl;
    cout << "ECDSA signature (signed by A): " << endl << ecdsaSignature.formattedHex << endl << endl;

    ECCPublicKey eccPublicKeyA = eciesA.getPublicKey();

    if (eciesB.verify(eccPublicKeyA, messageToSign, ecdsaSignature))
    {
        cout << "ECDSA signature verification (verified by B): VERIFIED" << endl;
    }
    else
    {
        cout << "ECDSA signature verification (verified by B): INVALID" << endl;
    }

    cout << "\nECIES Full Encryption - A:\n\n";

    ECIES::ECIESEncryptedBlock eciesEncryptedBlock = eciesA.fullEncryption(plaintextMessage, 
        strlen((char *)plaintextMessage) + 1);

    cout << "Ciphertext Hex: \n" << eciesEncryptedBlock.ciphertextHex << endl << endl;
    //cout << "Ciphertext: \n" << eciesEncryptedBlock.ciphertext << endl << endl;
    cout << "Ciphertext Size: " << eciesEncryptedBlock.ciphertextSize << endl << endl;
    cout << "MAC Hex: \n" << eciesEncryptedBlock.macHex << endl << endl;
    //cout << "MAC: \n" << eciesEncryptedBlock.mac << endl << endl;
    cout << "Standard Curve Name: " << eciesEncryptedBlock.publicKey.getDomainParams().standardCurveName << endl;
    
    unsigned char *ciphertextForMac;
    uint64_t s2Size = 0;
    uint64_t ciphertextSize = eciesEncryptedBlock.ciphertextSize;
    uint64_t ciphertextForMacSize = 0;

    string s2Temp = eciesB.getS2();

    // concat S2
    s2Size = s2Temp.length();

    if (s2Size > 0)
    {
        unsigned char *s2Bytes = (unsigned char *)malloc(s2Size * sizeof(unsigned char));
        std::copy(s2Temp.cbegin(), s2Temp.cend(), s2Bytes);

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

    if (eciesB.verifyMAC(ciphertextForMac, ciphertextForMacSize, eciesEncryptedBlock.mac) == true)
    {
        cout << "\nECIES Encrypted Block MAC verification (Verified by B): VERIFIED\n";
    }
    else
    {
        cout << "\nECIES Encrypted Block MAC verification (Verified by B): INVALID\n";
    }

    free(ciphertextForMac);
    
    uint64_t decryptedMessageLength = 0;
    unsigned char *decryptedMessageFromBlock = eciesB.fullDecryption(eciesEncryptedBlock, &decryptedMessageLength);

    cout << "\nDecrypted Message - B: \n" << decryptedMessageFromBlock << endl;
    cout << "\nDecrypted Message Size - B: " << decryptedMessageLength << endl;

    cout << "\nECIES Test Finished\n\n";
}

void fullTest()
{
    argon2Test();
    twofishTest();
    hashAndHMACTest();

    PolyElement r, a, b, x, y, dummy;
    ExtensionField extField(Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663"), 1, dummy);

    extField.Fp_X.assign(a, Integer("115792089237316195423570985008687907853269984665640564039457584007908834671662"));
    extField.Fp_X.assign(b, Integer("1"));
    
    extField.add(r, a, b);  
    cout << "r = ";
    extField.printPolyElement(r);
    cout << endl;

    extField.sqr(r, a);  
    cout << "r = ";
    extField.printPolyElement(r);
    cout << endl;

    extField.Fp_X.assign(x, Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240"));
    extField.Fp_X.assign(y, Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424"));

    ECPoint G(x, y);
    PolyElement A, B;

    extField.Fp_X.assign(A, Integer("0"));
    extField.Fp_X.assign(B, Integer("7"));

    EllipticCurveFq EC_Fq(Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663"), 
                            Integer("1"), dummy, ELLIPTIC_CURVE_TYPE::E_K, A, B, dummy, Integer("115792089237316195423570985008687907852837564279074904382605163141518161494337"));


    ExtensionField extField_secp192r1(Integer("6277101735386680763835789423207666416083908700390324961279"), 1, dummy);
    
    extField_secp192r1.sqr(r, a);  
    cout << "r2 = ";
    extField_secp192r1.printPolyElement(r);
    cout << endl;

    extField_secp192r1.Fp_X.assign(x, Integer("602046282375688656758213480587526111916698976636884684818"));
    extField_secp192r1.Fp_X.assign(y, Integer("174050332293622031404857552280219410364023488927386650641"));

    ECPoint G_secp192r1(x, y);
    PolyElement A_secp192r1, B_secp192r1;

    extField_secp192r1.Fp_X.assign(A_secp192r1, Integer("6277101735386680763835789423207666416083908700390324961276"));
    extField_secp192r1.Fp_X.assign(B_secp192r1, Integer("2455155546008943817740293915197451784769108058161191238065"));

    EllipticCurveFq E_Fq_secp192r1(Integer("6277101735386680763835789423207666416083908700390324961279"), 
                            1, dummy, ELLIPTIC_CURVE_TYPE::E_K, A_secp192r1, B_secp192r1, 
                            dummy, Integer("1"));

    // A:
    PolyElement dA;
    
    ECPoint Q;
    E_Fq_secp192r1.scalarMul(Q, G_secp192r1, Integer("6277101735386680763835789423176059013767194773182842284080"), Integer("6277101735386680763835789423176059013767194773182842284081"));
    cout << endl << endl;
    cout << "Q = ";
    Q.print();

    std::stringstream ss(std::stringstream::out | std::stringstream::binary);
    cout << "ss test: ";
    E_Fq_secp192r1.extField->Fp_X.write(ss << "", Q.getX());
    cout << ss.str();

    ss.clear();
    ss.str(string());
    ss << Q.getX().at(0);
    cout << "ss test 2: "<< ss.str();

    ECCKey eccKeyA, eccKeyB;
    ECCDomainParameters eccDomainParams;
    ECC ecc, ecc2;

    /*
    eccDomainParams.p = Integer("6277101735386680763835789423207666416083908700390324961279");
    eccDomainParams.a = Integer("6277101735386680763835789423207666416083908700390324961276");
    eccDomainParams.b = Integer("2455155546008943817740293915197451784769108058161191238065");
    eccDomainParams.Gx = Integer("602046282375688656758213480587526111916698976636884684818");
    eccDomainParams.Gy = Integer("174050332293622031404857552280219410364023488927386650641");
    eccDomainParams.n = Integer("6277101735386680763835789423176059013767194773182842284081");
    eccDomainParams.h = Integer("1");
    eccDomainParams.standardCurveName = "secp192r1";

    ecc.setDomainParams(eccDomainParams);
    */

    /*
    eccDomainParams.p = Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663");
    eccDomainParams.a = Integer("0");
    eccDomainParams.b = Integer("7");
    eccDomainParams.Gx = Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    eccDomainParams.Gy = Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    eccDomainParams.n = Integer("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    eccDomainParams.h = Integer("1");
    eccDomainParams.standardCurveName = "secp256k1";
    */

    eccDomainParams.p = Integer(convertBase("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16, 10).c_str());
    eccDomainParams.a = Integer(convertBase("0000000000000000000000000000000000000000000000000000000000000000", 16, 10).c_str());
    eccDomainParams.b = Integer(convertBase("0000000000000000000000000000000000000000000000000000000000000007", 16, 10).c_str());
    eccDomainParams.Gx = Integer(convertBase("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16, 10).c_str());
    eccDomainParams.Gy = Integer(convertBase("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16, 10).c_str());
    eccDomainParams.n = Integer(convertBase("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16, 10).c_str());
    eccDomainParams.h = Integer(convertBase("1", 16, 10).c_str());
    eccDomainParams.standardCurveName = "secp256k1";

    ecc.setDomainParams(eccDomainParams);
    
    eccKeyA = ecc.generateKeyPair();
    eccKeyB = ecc.generateKeyPair();

    cout << endl << "A's public key: ";
    eccKeyA.getQ().print();
    cout << endl;

    cout << endl << "A's private key: ";
    cout << eccKeyA.getd();
    cout << endl;

    cout << endl << "B's public key: ";
    eccKeyB.getQ().print();
    cout << endl;

    cout << endl << "B's private key: ";
    cout << eccKeyB.getd();
    cout << endl;

    //ecc2.setDomainParams(*StandardCurves::getECCDomainParametersByStandardCurveName("secp192r1"));
    ecc2.setDomainParams(*StandardCurves::getECCDomainParametersByStandardCurveName("secp256k1"));

    string sharedSecretA = ECDHE::generateSharedSecretKeyHash(ecc, eccKeyA, eccKeyB.getQ(), "BLAKE2b-256", "hex");
    string sharedSecretB = ECDHE::generateSharedSecretKeyHash(ecc2, eccKeyB, eccKeyA.getQ(), "BLAKE2b-256", "hex");
    string sharedSecretA_BLAKE2b = ECDHE::generateSharedSecretKeyHash(ecc, eccKeyA, eccKeyB.getQ(), "BLAKE2b", "hex");
    string sharedSecretB_BLAKE2b = ECDHE::generateSharedSecretKeyHash(ecc2, eccKeyB, eccKeyA.getQ(), "BLAKE2b", "hex");
    string sharedSecretA_SHA_256 = ECDHE::generateSharedSecretKeySHA256(ecc, eccKeyA, eccKeyB.getQ());
    string sharedSecretB_SHA_256 = ECDHE::generateSharedSecretKeySHA256(ecc2, eccKeyB, eccKeyA.getQ());
    ECPoint sharedSecretAECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKeyA, eccKeyB.getQ());
    string sharedSecretA_SHA_3_512 = ECDHE::generateSharedSecretKeySHA3_512(ecc, eccKeyA, eccKeyB.getQ());
    string sharedSecretB_SHA_3_512 = ECDHE::generateSharedSecretKeySHA3_512(ecc2, eccKeyB, eccKeyA.getQ());

    cout << endl << endl;
    cout << "A's shared secret - BLAKE2b-256: " << sharedSecretA << endl;
    cout << "B's shared secret - BLAKE2b-256: " << sharedSecretB << endl;

    cout << endl << endl;
    cout << "A's shared secret - BLAKE2b: " << sharedSecretA_BLAKE2b << endl;
    cout << "B's shared secret - BLAKE2b: " << sharedSecretB_BLAKE2b << endl;

    cout << endl << endl;
    cout << "A's shared secret ec point: ";
    sharedSecretAECPoint.print();

    cout << endl << endl;
    cout << "A's shared secret SHA3-512: " << sharedSecretA_SHA_3_512 << endl;
    cout << "B's shared secret SHA3-512: " << sharedSecretB_SHA_3_512 << endl;

    cout << "-------------------\n";
    cout << "Symmetric encryption - A - ECDHE A's shared secret drived using SHA-256 - Twofish 256-bit key CBC with IV = c1f6fd873e14050697c168b3e9da5db2" << endl;
    cout << "-------------------\n";
    unsigned char *plaintextMessage = (unsigned char *)"This is a message from A to B. Hi B, I hope you're doing well. I'm A, can you please help me in programming course?";
    uint64_t length = 0;
    char *ciphertextMessage = twofishEncrypt_256_CBC_PKCS7_Hex(sharedSecretA.c_str(), 
        "c1f6fd873e14050697c168b3e9da5db2", plaintextMessage, strlen((char *)plaintextMessage), &length);
    cout << "[Plaintext]: \n" << plaintextMessage << "\n\n[Ciphertext]: \n" << ciphertextMessage << endl << endl;

    cout << "-------------------\n";
    cout << "Symmetric decryption - B - ECDHE B's shared secret drived using SHA-256 - Twofish 256-bit key CBC with IV = c1f6fd873e14050697c168b3e9da5db2" << endl;
    cout << "-------------------\n";
    unsigned char *decryptedMessage = twofishDecrypt_256_CBC_PKCS7_Hex(sharedSecretB.c_str(), 
        "c1f6fd873e14050697c168b3e9da5db2", ciphertextMessage, &length);
    cout << "[Ciphertext]: \n" << ciphertextMessage << "\n\n[Decrypted]: \n" << decryptedMessage << endl << endl;
    cout << "-------------------\n";

    cout << "secp192r1 Hex:\n\n";
    string decimal = convertBase(StandardCurves::secp192r1.p, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "p=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.a, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "a=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.b, 16, 10);            
    decimal = convertBase(decimal, 10, 16);
    cout << "b=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp192r1.Gx, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "Gx=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp192r1.Gy, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "Gy=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp192r1.n, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "n=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.h, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "h=" << decimal << endl;



    cout << "\nsecp192r1 Decimal:\n\n";
    decimal = convertBase(StandardCurves::secp192r1.p, 16, 10);
    cout << "p=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.a, 16, 10);
    cout << "a=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.b, 16, 10);
    cout << "b=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp192r1.Gx, 16, 10);
    cout << "Gx=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.Gy, 16, 10);
    cout << "Gy=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp192r1.n, 16, 10);
    cout << "n=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp192r1.h, 16, 10);
    cout << "h=" << decimal << endl;



    cout << "\n\nsecp256k1 Hex:\n\n";
    decimal = convertBase(StandardCurves::secp256k1.p, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "p=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.a, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "a=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.b, 16, 10);            
    decimal = convertBase(decimal, 10, 16);
    cout << "b=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp256k1.Gx, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "Gx=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp256k1.Gy, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "Gy=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp256k1.n, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "n=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.h, 16, 10);
    decimal = convertBase(decimal, 10, 16);
    cout << "h=" << decimal << endl;


    cout << "\nsecp256k1 Decimal:\n\n";
    decimal = convertBase(StandardCurves::secp256k1.p, 16, 10);
    cout << "p=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.a, 16, 10);
    cout << "a=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.b, 16, 10);
    cout << "b=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp256k1.Gx, 16, 10);
    cout << "Gx=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.Gy, 16, 10);
    cout << "Gy=" << decimal << endl;

    decimal = convertBase(StandardCurves::secp256k1.n, 16, 10);
    cout << "n=" << decimal << endl;
    
    decimal = convertBase(StandardCurves::secp256k1.h, 16, 10);
    cout << "h=" << decimal << endl;


    ///////////////

    cout << "---------------------------------";

    string message = "Hello message to sign";

    ECDSA::ECDSASignature ecdsaSignature = ECDSA::sign(ecc, eccKeyA, "sha3-256", message);

    cout << endl << endl;
    cout << "ECDSA signature (signed by A): " << ecdsaSignature.formattedHex << endl << endl;

    ECPoint eccPublicKeyA = eccKeyA.getQ();

    if (ECDSA::verify(ecc2, eccPublicKeyA, "sha3-256", message, ecdsaSignature))
    {
        cout << "ECDSA signature verification (verified by B): VERIFIED" << endl;
    }
    else
    {
        cout << "ECDSA signature verification (verified by B): INVALID" << endl;
    }

    ///////////////
    
    cout << "---------------------------------";

    message = "Hello message to sign with EC Elgamal";

    ECElGamal::ECElGamalSignature ecelgamalSignature = ECElGamal::sign(ecc, eccKeyA, "sha3-256", message);

    cout << endl << endl;
    cout << "EC ElGamal signature (signed by A): " << ecelgamalSignature.formattedHex << endl << endl;

    eccPublicKeyA = eccKeyA.getQ();

    if (ECElGamal::verify(ecc2, eccPublicKeyA, "sha3-256", message, ecelgamalSignature))
    {
        cout << "EC ElGamal signature verification (verified by B): VERIFIED" << endl;
    }
    else
    {
        cout << "EC ElGamal signature verification (verified by B): INVALID" << endl;
    }
    
    cout << "---------------------------------";

    ECPoint ecPointMessage;
    ECPoint ecPointDecMessage;
    PolyElement xTemp, yTemp;
    ECElGamal::ECElGamalCiphertextTuple ecelgamalC;

    ecc.E_Fq->extField->Fp_X.assign(xTemp, Integer("18400947891253882488466418348028273465295156757822764189886090079956310523881"));
    ecc.E_Fq->extField->Fp_X.assign(yTemp, Integer("107091053700274347768154293508622746194696633634219891752586853826735667420748"));
    
    ecPointMessage.setXY(xTemp, yTemp);
    
    cout << "\nEC ElGamal Encryption: \n\nPlaintext EC Point: ";
    ecPointMessage.print();
    cout << endl << endl;

    eccPublicKeyA = eccKeyA.getQ();
    ecelgamalC = ECElGamal::encrypt(ecc2, eccPublicKeyA, ecPointMessage);
    
    cout << "Ciphertext Tuple {C1, C2} - Encrypted by B: ";
    cout << ecelgamalC.formattedHex;
    cout << endl << endl;


    ecPointDecMessage = ECElGamal::decrypt(ecc, eccKeyA.getd(), ecelgamalC);
    
    cout << "Decrypted EC Point - Decrypted by A: ";
    ecPointDecMessage.print();
    cout << endl << endl;

    ecc.print();
    cout << "------------";
    ecc2.print();

    cout << "-------------------------------------";

    cout << endl << "A's public key: ";
    eccKeyA.getQ().print();
    cout << endl;

    cout << endl << "A's public key x hex: ";
    cout << eccKeyA.getQ_X_InBase(&ecc, 16);
    cout << endl;

    cout << endl << "A's public key y hex: ";
    cout << eccKeyA.getQ_Y_InBase(&ecc, 16);
    cout << endl;

    cout << endl << "A's private key: ";
    cout << eccKeyA.getd();
    cout << endl;

    cout << endl << "A's private key hex: ";
    cout << eccKeyA.getd_InBase(16);
    cout << endl;

    eciesTest();
}

int main(int argc, char** argv)
{
    eciesTest();
    fullTest();

    return 0;
}