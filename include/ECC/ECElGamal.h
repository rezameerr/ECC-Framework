#ifndef __ECELGAMAL_H__
#define __ECELGAMAL_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "ECC.h"
#include "ECCPrivateKey.h"

class ECElGamal
{
private:
    static ECPoint mapMessageToECPoint(ECC ecc, const string m);
    static Integer hash(ECC ecc, string hashFunctionName, const string m);

public:
    struct ECElGamalCiphertextTuple
    {
        ECPoint c1;
        ECPoint c2;

        string rawHex;
        string rawDec;

        string formattedHex;
        string formattedDec;
    };

    struct ECElGamalSignature
    {
        ECPoint r;
        Integer s;

        string rawHex;
        string rawDec;

        string formattedHex;
        string formattedDec;
    };

    ECElGamal();
    ~ECElGamal();

    static ECElGamalCiphertextTuple encrypt(ECC ecc, ECPoint Q, ECPoint message);
    static ECElGamalCiphertextTuple encrypt(ECC ecc, ECCKey eccKey, ECPoint message);
    static ECElGamalCiphertextTuple encrypt(ECC ecc, ECCPublicKey publicKey, ECPoint message);

    static ECPoint decrypt(ECC ecc, Integer d, ECElGamalCiphertextTuple ciphertext);
    static ECPoint decrypt(ECC ecc, ECCKey eccKey, ECElGamalCiphertextTuple ciphertext);
    static ECPoint decrypt(ECC ecc, ECCPrivateKey eccPrivateKey, ECElGamalCiphertextTuple ciphertext);

    static ECElGamalSignature sign(ECC ecc, Integer d, string hashFunctionName, const string message);
    static ECElGamalSignature sign(ECC ecc, ECCKey eccKey, string hashFunctionName, const string message);
    static ECElGamalSignature sign(ECC ecc, ECCPrivateKey eccPrivateKey, string hashFunctionName, const string message);

    static ECElGamalSignature sign(ECC ecc, Integer d, ECPoint message);
    static ECElGamalSignature sign(ECC ecc, ECCKey eccKey, ECPoint message);
    static ECElGamalSignature sign(ECC ecc, ECCPrivateKey eccPrivateKey, ECPoint message);

    static bool verify(ECC ecc, ECPoint Q, string hashFunctionName, const string message, ECElGamalSignature ecelgamalSignature);
    static bool verify(ECC ecc, ECCPublicKey eccPublicKey, string hashFunctionName, const string message, ECElGamalSignature ecelgamalSignature);

    static bool verify(ECC ecc, ECPoint Q, ECPoint message, ECElGamalSignature ecelgamalSignature);
    static bool verify(ECC ecc, ECCPublicKey eccPublicKey, ECPoint message, ECElGamalSignature ecelgamalSignature);
};

#endif // __ECELGAMAL_H__