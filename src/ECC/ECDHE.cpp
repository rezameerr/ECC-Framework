#include "../../include/ECC/ECDHE.h"
#include "../../include/Cryptography/HashFunctions.h"

ECDHE::ECDHE()
{
}

ECDHE::~ECDHE()
{
}

ECPoint ECDHE::generateSharedSecretECPoint(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint;

    ecc.E_Fq->scalarMul(sharedSecretECPoint, Q, d, ecc.domainParams->n);

    return sharedSecretECPoint;
}

ECPoint ECDHE::generateSharedSecretECPoint(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    return ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
}

ECPoint ECDHE::generateSharedSecretECPoint(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    return ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
}

ECPoint ECDHE::generateSharedSecretECPoint(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    return ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
}

string ECDHE::generateSharedSecretKey(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return integerToString(sharedSecretECPointX);
}

string ECDHE::generateSharedSecretKey(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    return ECDHE::generateSharedSecretKey(ecc, eccKey.getd(), Q);
}

string ECDHE::generateSharedSecretKey(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    return ECDHE::generateSharedSecretKey(ecc, eccKey.getd(), eccPublicKey.Q);
}

string ECDHE::generateSharedSecretKey(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    return ECDHE::generateSharedSecretKey(ecc, eccPrivateKey.d, eccPublicKey.Q);
}

string ECDHE::generateSharedSecretKeyHash(ECC ecc, Integer d, ECPoint Q, string algorithm, string format)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);
    
    return HashFunctions::getHash(integerToString(sharedSecretECPointX), algorithm, format);
}

string ECDHE::generateSharedSecretKeyHash(ECC ecc, ECCKey eccKey, ECPoint Q, string algorithm, string format)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);
    
    return HashFunctions::getHash(integerToString(sharedSecretECPointX), algorithm, format);
}

string ECDHE::generateSharedSecretKeyHash(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey, string algorithm, string format)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), algorithm, format);
}

string ECDHE::generateSharedSecretKeyHash(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey, string algorithm, string format)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);
    
    return HashFunctions::getHash(integerToString(sharedSecretECPointX), algorithm, format);
}

string ECDHE::generateSharedSecretKeyMD5(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "md5", "hex");
}

string ECDHE::generateSharedSecretKeyMD5(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "md5", "hex");
}

string ECDHE::generateSharedSecretKeyMD5(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "md5", "hex");
}

string ECDHE::generateSharedSecretKeyMD5(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "md5", "hex");
}

string ECDHE::generateSharedSecretKeySHA256(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha256", "hex");
}

string ECDHE::generateSharedSecretKeySHA256(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha256", "hex");
}

string ECDHE::generateSharedSecretKeySHA256(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha256", "hex");
}

string ECDHE::generateSharedSecretKeySHA256(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha256", "hex");
}

string ECDHE::generateSharedSecretKeySHA512(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha512", "hex");
}

string ECDHE::generateSharedSecretKeySHA512(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);
    
    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha512", "hex");
}

string ECDHE::generateSharedSecretKeySHA512(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha512", "hex");
}

string ECDHE::generateSharedSecretKeySHA512(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha512", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_256(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-256", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_256(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-256", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_256(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-256", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_256(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-256", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_512(ECC ecc, Integer d, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, d, Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-512", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_512(ECC ecc, ECCKey eccKey, ECPoint Q)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-512", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_512(ECC ecc, ECCKey eccKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccKey.getd(), eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-512", "hex");
}

string ECDHE::generateSharedSecretKeySHA3_512(ECC ecc, ECCPrivateKey eccPrivateKey, ECCPublicKey eccPublicKey)
{
    ECPoint sharedSecretECPoint = ECDHE::generateSharedSecretECPoint(ecc, eccPrivateKey.d, eccPublicKey.Q);
    Integer sharedSecretECPointX = ecc.E_Fq->elementToInteger(sharedSecretECPoint.getX(), ecc.domainParams->n);

    return HashFunctions::getHash(integerToString(sharedSecretECPointX), "sha3-512", "hex");
}

/*------------------- BLAKE family ----------------------*/
// Although it's only for symmetric key extraction from shared secret point, 
//      it's safer to use a more secure hash algorithm.
//