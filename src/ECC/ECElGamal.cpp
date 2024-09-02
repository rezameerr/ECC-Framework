#include "../../include/ECC/ECElGamal.h"
#include "../../include/Cryptography/HashFunctions.h"

ECElGamal::ECElGamal()
{
}

ECElGamal::~ECElGamal()
{
}

ECPoint ECElGamal::mapMessageToECPoint(ECC ecc, const string m)
{
    ECPoint ecPointM;

    // TO-DO: Should be implemented

    return ecPointM;
}

Integer ECElGamal::hash(ECC ecc, string hashFunctionName, const string m)
{
    stringToLowercase(hashFunctionName);
    string hexHash = HashFunctions::getHash(m, hashFunctionName, "hex");
    Integer intHash = Integer(convertBase(hexHash, 16, 10).c_str());

    intHash %= ecc.domainParams->n;

    return intHash;
}

ECElGamal::ECElGamalCiphertextTuple ECElGamal::encrypt(ECC ecc, ECPoint Q, ECPoint message)
{
    ECElGamalCiphertextTuple ecelgamalCiphertextTuple;
    ECPoint c1, c2, temp;
    Integer k;

    k = ecc.generateSecureRandomIntegerOverE_Fq();

    //ecc.E_Fq->scalarMul(c1, ecc.G, k, ecc.getDomainParams().n);
    ecc.E_Fq->scalarMul(c1, ecc.G, k, ecc.domainParams->n);
    ecc.E_Fq->scalarMul(temp, Q, k, ecc.domainParams->n);
    ecc.E_Fq->add(c2, temp, message);

    string c1_X_Dec = integerToString(ecc.E_Fq->elementToInteger(c1.getX(), ecc.domainParams->n));
    string c1_Y_Dec = integerToString(ecc.E_Fq->elementToInteger(c1.getY(), ecc.domainParams->n));
    string c2_X_Dec = integerToString(ecc.E_Fq->elementToInteger(c2.getX(), ecc.domainParams->n));
    string c2_Y_Dec = integerToString(ecc.E_Fq->elementToInteger(c2.getY(), ecc.domainParams->n));
    string c1_X_Hex = integerToString(ecc.E_Fq->elementToInteger(c1.getX(), ecc.domainParams->n), 16);
    string c1_Y_Hex = integerToString(ecc.E_Fq->elementToInteger(c1.getY(), ecc.domainParams->n), 16);
    string c2_X_Hex = integerToString(ecc.E_Fq->elementToInteger(c2.getX(), ecc.domainParams->n), 16);
    string c2_Y_Hex = integerToString(ecc.E_Fq->elementToInteger(c2.getY(), ecc.domainParams->n), 16);

    ecelgamalCiphertextTuple.c1 = c1;
    ecelgamalCiphertextTuple.c2 = c2;
    ecelgamalCiphertextTuple.rawDec = c1_X_Dec + "," + c1_Y_Dec + ";" + c2_X_Dec + "," + c2_Y_Dec;
    ecelgamalCiphertextTuple.rawHex = c1_X_Hex + "," + c1_Y_Hex + ";" + c2_X_Hex + "," + c2_Y_Hex;
    ecelgamalCiphertextTuple.formattedDec = "{(" + c1_X_Dec + ", " + c1_Y_Dec + "), (" + c2_X_Dec + ", " + c2_Y_Dec + ")}";
    ecelgamalCiphertextTuple.formattedHex = "{(0x" + c1_X_Hex + ", 0x" + c1_Y_Hex + "), (0x" + c2_X_Hex + ", 0x" + c2_Y_Hex + ")}";

    return ecelgamalCiphertextTuple;
}

ECElGamal::ECElGamalCiphertextTuple ECElGamal::encrypt(ECC ecc, ECCKey eccKey, ECPoint message)
{
    return ECElGamal::encrypt(ecc, eccKey.getQ(), message);
}

ECElGamal::ECElGamalCiphertextTuple ECElGamal::encrypt(ECC ecc, ECCPublicKey publicKey, ECPoint message)
{
    return ECElGamal::encrypt(ecc, publicKey.Q, message);
}

ECPoint ECElGamal::decrypt(ECC ecc, Integer d, ECElGamalCiphertextTuple ciphertext)
{
    ECElGamalCiphertextTuple ecelgamalCiphertextTuple;
    ECPoint dc1, dc1Inv, decryptedMessage;

    ecc.E_Fq->scalarMul(dc1, ciphertext.c1, d, ecc.domainParams->n);
    ecc.E_Fq->inv(dc1Inv, dc1);
    ecc.E_Fq->add(decryptedMessage, ciphertext.c2, dc1Inv);

    return decryptedMessage;
}

ECPoint ECElGamal::decrypt(ECC ecc, ECCKey eccKey, ECElGamalCiphertextTuple ciphertext)
{
    return ECElGamal::decrypt(ecc, eccKey.getd(), ciphertext);
}

ECPoint ECElGamal::decrypt(ECC ecc, ECCPrivateKey eccPrivateKey, ECElGamalCiphertextTuple ciphertext)
{
    return ECElGamal::decrypt(ecc, eccPrivateKey.d, ciphertext);
}

ECElGamal::ECElGamalSignature ECElGamal::sign(ECC ecc, Integer d, string hashFunctionName, const string message)
{
    ECElGamalSignature ecelgamalSignature;
    ECPoint r;
    Integer hM, k, r_x, kInv, s;

    hM = hash(ecc, hashFunctionName, message);

    do
    {
        do
        {
            k = ecc.generateSecureRandomIntegerOverE_Fq();
        } while (gcd(k, ecc.domainParams->n) != 1);
        
        ecc.E_Fq->scalarMul(r, ecc.G, k, ecc.domainParams->n);
        r_x = ecc.E_Fq->elementToInteger(r.getX(), ecc.domainParams->n);
        kInv = k;
        invin(kInv, ecc.domainParams->n);
        s = ((hM - (d * r_x)) * kInv) % ecc.domainParams->n;

        if (s <= 0)
        {
            s += ecc.domainParams->n;
        }
    } while (s == 0);
    
    string r_X_Dec = integerToString(ecc.E_Fq->elementToInteger(r.getX(), ecc.domainParams->n));
    string r_Y_Dec = integerToString(ecc.E_Fq->elementToInteger(r.getY(), ecc.domainParams->n));
    string r_X_Hex = integerToString(ecc.E_Fq->elementToInteger(r.getX(), ecc.domainParams->n), 16);
    string r_Y_Hex = integerToString(ecc.E_Fq->elementToInteger(r.getY(), ecc.domainParams->n), 16);
    string sDec = integerToString(s);
    string sHex = integerToString(s, 16);

    ecelgamalSignature.r = r;
    ecelgamalSignature.s = s;
    ecelgamalSignature.rawDec = r_X_Dec + "," + r_Y_Dec + ";" + sDec;
    ecelgamalSignature.rawHex = r_X_Hex + "," + r_Y_Hex + ";" + sHex;
    ecelgamalSignature.formattedDec = "{r=(" + r_X_Dec + ", " + r_Y_Dec + "), s=" + sDec + "}";
    ecelgamalSignature.formattedHex = "{r=(0x" + r_X_Hex + ", 0x" + r_Y_Hex + "), s=0x" + sHex + "}";

    return ecelgamalSignature;
}

ECElGamal::ECElGamalSignature ECElGamal::sign(ECC ecc, ECCKey eccKey, string hashFunctionName, const string message)
{
    return ECElGamal::sign(ecc, eccKey.getd(), hashFunctionName, message);
}

ECElGamal::ECElGamalSignature ECElGamal::sign(ECC ecc, ECCPrivateKey eccPrivateKey, string hashFunctionName, const string message)
{
    return ECElGamal::sign(ecc, eccPrivateKey.d, hashFunctionName, message);
}

ECElGamal::ECElGamalSignature ECElGamal::sign(ECC ecc, Integer d, ECPoint message)
{
    ECElGamal::ECElGamalSignature ecelgamalSignature;

    // TO-DO: mapping function should be implemented

    return ecelgamalSignature;
}

ECElGamal::ECElGamalSignature ECElGamal::sign(ECC ecc, ECCKey eccKey, ECPoint message)
{
    return ECElGamal::sign(ecc, eccKey.getd(), message);
}

ECElGamal::ECElGamalSignature ECElGamal::sign(ECC ecc, ECCPrivateKey eccPrivateKey, ECPoint message)
{
    return ECElGamal::sign(ecc, eccPrivateKey.d, message);
}

bool ECElGamal::verify(ECC ecc, ECPoint Q, string hashFunctionName, const string message, ECElGamalSignature ecelgamalSignature)
{
    Integer hM, r_x, s;
    ECPoint hMG, Qr, rs, Qrrs;

    hM = hash(ecc, hashFunctionName, message);
    r_x = ecc.E_Fq->elementToInteger(ecelgamalSignature.r.getX(), ecc.domainParams->n);
    s = ecelgamalSignature.s;

    if (r_x <= 0 || r_x >= ecc.domainParams->n)
    {
        return false;
    }

    if (s <= 0 || s >= (ecc.domainParams->n - 1))
    {
        return false;
    }

    ecc.E_Fq->scalarMul(hMG, ecc.G, hM, ecc.domainParams->n);
    
    ecc.E_Fq->scalarMul(Qr, Q, r_x, ecc.domainParams->n);
    ecc.E_Fq->scalarMul(rs, ecelgamalSignature.r, s, ecc.domainParams->n);
    ecc.E_Fq->add(Qrrs, Qr, rs);

    if (hMG == Qrrs)
    {
        return true;
    }

    return false;
}

bool ECElGamal::verify(ECC ecc, ECCPublicKey eccPublicKey, string hashFunctionName, const string message, ECElGamalSignature ecelgamalSignature)
{
    return ECElGamal::verify(ecc, eccPublicKey.Q, hashFunctionName, message, ecelgamalSignature);
}

bool ECElGamal::verify(ECC ecc, ECPoint Q, ECPoint message, ECElGamalSignature ecelgamalSignature)
{
    // TO-DO: mapping function should be implemented
    
    return false;
}

bool ECElGamal::verify(ECC ecc, ECCPublicKey eccPublicKey, ECPoint message, ECElGamalSignature ecelgamalSignature)
{
    return ECElGamal::verify(ecc, eccPublicKey.Q, message, ecelgamalSignature);
}

