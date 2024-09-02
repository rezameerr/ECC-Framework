#ifndef __ECDHE_H__
#define __ECDHE_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "../Math/EllipticCurveFq.h"
#include "ECCDomainParameters.h"
#include "ECC.h"
#include "ECCKey.h"
#include "ECCPrivateKey.h"
#include "ECCPublicKey.h"

class ECDHE
{
private:

public:
    ECDHE();
    ~ECDHE();

    static ECPoint generateSharedSecretECPoint(ECC ecc, Integer d, ECPoint Q);
    static ECPoint generateSharedSecretECPoint(ECC ecc, ECCKey eccKey, ECPoint Q);
    static ECPoint generateSharedSecretECPoint(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static ECPoint generateSharedSecretECPoint(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);
    
    static string generateSharedSecretKey(ECC ecc, Integer d, ECPoint Q);
    static string generateSharedSecretKey(ECC ecc, ECCKey eccKey, ECPoint Q);
    static string generateSharedSecretKey(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static string generateSharedSecretKey(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);
    
    static string generateSharedSecretKeyHash(ECC ecc, Integer d, ECPoint Q, string algorithm, string format);
    static string generateSharedSecretKeyHash(ECC ecc, ECCKey eccKey, ECPoint Q, string algorithm, string format);
    static string generateSharedSecretKeyHash(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey, string algorithm, string format);
    static string generateSharedSecretKeyHash(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey, string algorithm, string format);
    
    static string generateSharedSecretKeyMD5(ECC ecc, Integer d, ECPoint Q);
    static string generateSharedSecretKeyMD5(ECC ecc, ECCKey eccKey, ECPoint Q);
    static string generateSharedSecretKeyMD5(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static string generateSharedSecretKeyMD5(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);

    static string generateSharedSecretKeySHA256(ECC ecc, Integer d, ECPoint Q);
    static string generateSharedSecretKeySHA256(ECC ecc, ECCKey eccKey, ECPoint Q);
    static string generateSharedSecretKeySHA256(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static string generateSharedSecretKeySHA256(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);

    static string generateSharedSecretKeySHA512(ECC ecc, Integer d, ECPoint Q);
    static string generateSharedSecretKeySHA512(ECC ecc, ECCKey eccKey, ECPoint Q);
    static string generateSharedSecretKeySHA512(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static string generateSharedSecretKeySHA512(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);

    static string generateSharedSecretKeySHA3_256(ECC ecc, Integer d, ECPoint Q);
    static string generateSharedSecretKeySHA3_256(ECC ecc, ECCKey eccKey, ECPoint Q);
    static string generateSharedSecretKeySHA3_256(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static string generateSharedSecretKeySHA3_256(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);

    static string generateSharedSecretKeySHA3_512(ECC ecc, Integer d, ECPoint Q);
    static string generateSharedSecretKeySHA3_512(ECC ecc, ECCKey eccKey, ECPoint Q);
    static string generateSharedSecretKeySHA3_512(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey);
    static string generateSharedSecretKeySHA3_512(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey);
};

#endif // __ECDHE_H__