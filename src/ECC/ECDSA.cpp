#include "../../include/ECC/ECDSA.h"
#include "../../include/Cryptography/HashFunctions.h"

/*
ECDSA::ECDSA(ECC ecc, const string hashFunctionName)
{
    this->ecc = ecc;
    this->hashFunctionName = hashFunctionName;
    stringToLowercase(this->hashFunctionName);
}

ECDSA::~ECDSA()
{
}

Integer ECDSA::hash(const string m)
{
    string hexHash = HashFunctions::getHash(m, hashFunctionName, "hex");
    Integer intHash = Integer(convertBase(hexHash, 16, 10).c_str());

    /////////////////
    // z = L_z(n bit)
    //
    //
    /////////////////

    intHash %= ecc.domainParams->n;

    return intHash;
}

void ECDSA::setParameters(ECC ecc, const string hashFunctionName)
{
    this->ecc = ecc;
    this->hashFunctionName = hashFunctionName;
    stringToLowercase(this->hashFunctionName);
}

ECC ECDSA::getECC()
{
    return ecc;
}

void ECDSA::setECC(ECC ecc)
{
    this->ecc = ecc;
}

const string ECDSA::gethashFunctionName()
{
    return hashFunctionName;
}

void ECDSA::sethashFunctionName(const string hashFunctionName)
{
    this->hashFunctionName = hashFunctionName;
    stringToLowercase(this->hashFunctionName);
}
*/

ECDSA::ECDSA()
{
}

ECDSA::~ECDSA()
{
}

Integer ECDSA::hash(ECC ecc, string hashFunctionName, const string m)
{
    stringToLowercase(hashFunctionName);
    string hexHash = HashFunctions::getHash(m, hashFunctionName, "hex");
    Integer intHash = Integer(convertBase(hexHash, 16, 10).c_str());

    /////////////////
    // z = L_z(n bit)
    //
    //
    /////////////////

    intHash %= ecc.domainParams->n;

    return intHash;
}

ECDSA::ECDSASignature ECDSA::sign(ECC ecc, Integer d, string hashFunctionName, const string message)
{
    ECDSASignature ecdsaSignature { 0, 0, "", "", "", "" };
    Integer e, k, k_inv, x, r, s;

    stringToLowercase(hashFunctionName);
    e = k = x = r = s = 0;

    e = hash(ecc, hashFunctionName, message);

    do
    {
        do
        {
            ECPoint p;
            k = ecc.generateSecureRandomIntegerOverE_Fq();
            ecc.E_Fq->scalarMul(p, ecc.G, k, ecc.domainParams->n);
            Integer x = ecc.E_Fq->elementToInteger(p.getX(), ecc.domainParams->n);
            r = x % ecc.domainParams->n;
        } while (r == 0);

        k_inv = invin(k, ecc.domainParams->n);
        s = (k_inv * (e + (r * d))) % ecc.domainParams->n;    
    } while (s == 0);
    
    string rDec = integerToString(r);
    string sDec = integerToString(s);
    string rHex = convertBase(rDec, 10, 16);
    string sHex = convertBase(sDec, 10, 16);
    //string rHex = integerToString(r, 16);
    //string sHex = integerToString(s, 16);

    ecdsaSignature.r = r;
    ecdsaSignature.s = s;
    ecdsaSignature.rawDec = rDec + "," + sDec;
    ecdsaSignature.rawHex = rHex + "," + sHex;
    ecdsaSignature.formattedDec = "r=" + rDec + ", s=" + sDec;
    ecdsaSignature.formattedHex = "r=0x" + rHex + ", s=0x" + sHex;

    return ecdsaSignature;
}

ECDSA::ECDSASignature ECDSA::sign(ECC ecc, ECCKey eccKey, string hashFunctionName, const string message)
{
    return sign(ecc, eccKey.getd(), hashFunctionName, message);
}

ECDSA::ECDSASignature ECDSA::sign(ECC ecc, ECCPrivateKey eccPrivateKey, string hashFunctionName, const string message)
{
    return sign(ecc, eccPrivateKey.d, hashFunctionName, message);
}

bool ECDSA::verify(ECC ecc, ECPoint Q, string hashFunctionName, const string message, ECDSASignature ecdsaSignature)
{
    if (ecdsaSignature.r < 1 || ecdsaSignature.r > ecc.domainParams->n - 1 || 
        ecdsaSignature.s < 1 || ecdsaSignature.s > ecc.domainParams->n - 1)
    {
        return false;
    }

    if (!ecc.validatePublicKey(Q))
    {
        return false;
    }

    Integer e, u1, u2, r, s, s_inv, x;
    ECPoint p1, p2, p3;

    stringToLowercase(hashFunctionName);
    e = u1 = u2 = r = s = s_inv = x = 0;
    //p1.setIdentity(false);
    //p2.setIdentity(false);
    //p3.setIdentity(false);

    r = ecdsaSignature.r;
    s = ecdsaSignature.s;

    s_inv = invin(s, ecc.domainParams->n);
    e = hash(ecc, hashFunctionName, message);

    u1 = (e * s_inv) % ecc.domainParams->n;
    u2 = (r * s_inv) % ecc.domainParams->n;

    ecc.E_Fq->scalarMul(p1, ecc.G, u1, ecc.domainParams->n);
    ecc.E_Fq->scalarMul(p2, Q, u2, ecc.domainParams->n);
    ecc.E_Fq->add(p3, p1, p2);

    if (p3.getIdentity())
    {
        return false;
    }

    x = ecc.E_Fq->elementToInteger(p3.getX(), ecc.domainParams->n);

    if (r == x % ecc.domainParams->n)
    {
        return true;
    }

    return false;
}

bool ECDSA::verify(ECC ecc, ECCPublicKey eccPublicKey, string hashFunctionName, const string message, ECDSASignature ecdsaSignature)
{
    return verify(ecc, eccPublicKey.Q, hashFunctionName, message, ecdsaSignature);
}
