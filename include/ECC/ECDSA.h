#ifndef __ECDSA_H__
#define __ECDSA_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "../Math/EllipticCurveFq.h"
#include "ECCDomainParameters.h"
#include "ECC.h"
#include "ECCKey.h"
#include "ECCPrivateKey.h"
#include "ECCPublicKey.h"
#include <string>

using namespace std;

class ECDSA
{
private:
    /*
    ECC ecc;
    string hashFunctionName;
    */
    static Integer hash(ECC ecc, string hashFunctionName, const string m);

public:
    struct ECDSASignature
    {
        Integer r;
        Integer s;

        string rawHex;
        string rawDec;

        string formattedHex;
        string formattedDec;
    };

    ECDSA();
    ~ECDSA();

    /*
    ECDSA(ECC ecc, const string hashFunctionName);
    ~ECDSA();

    void setParameters(ECC ecc, const string hashFunctionName);

    ECC getECC();
    void setECC(ECC ecc);

    const string gethashFunctionName();
    void sethashFunctionName(const string hashFunctionName);
    */
   
    static ECDSASignature sign(ECC ecc, Integer d, string hashFunctionName, const string message);
    static ECDSASignature sign(ECC ecc, ECCKey eccKey, string hashFunctionName, const string message);
    static ECDSASignature sign(ECC ecc, ECCPrivateKey eccPrivateKey, string hashFunctionName, const string message);

    static bool verify(ECC ecc, ECPoint Q, string hashFunctionName, const string message, ECDSASignature ecdsaSignature);
    static bool verify(ECC ecc, ECCPublicKey eccPublicKey, string hashFunctionName, const string message, ECDSASignature ecdsaSignature);
};

#endif // __ECDSA_H__