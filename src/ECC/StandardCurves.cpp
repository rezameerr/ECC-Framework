#include "../../include/Utils/Common.h"
#include "../../include/ECC/ECCDomainParameters.h"
#include "../../include/ECC/StandardCurves.h"
#include <iostream>

using namespace std;

StandardCurves::StandardCurve StandardCurves::secp256k1
{
    "secp256k1",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000007",
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    "1"
};

StandardCurves::StandardCurve StandardCurves::secp192r1
{
    "secp192r1",
    "fffffffffffffffffffffffffffffffeffffffffffffffff",
    "fffffffffffffffffffffffffffffffefffffffffffffffc",
    "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
    "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
    "1"
};

StandardCurves::StandardCurves()
{
}

StandardCurves::~StandardCurves()
{
}

ECCDomainParameters* StandardCurves::getECCDomainParametersByStandardCurveName(string curveName)
{
    ECCDomainParameters *eccDomainParams = nullptr;
    StandardCurve standardCurve;

    if (curveName == "secp256k1")
    {
        eccDomainParams = new ECCDomainParameters();

        eccDomainParams->p = Integer(convertBase(StandardCurves::secp256k1.p, 16, 10).c_str());
        eccDomainParams->a = Integer(convertBase(StandardCurves::secp256k1.a, 16, 10).c_str());
        eccDomainParams->b = Integer(convertBase(StandardCurves::secp256k1.b, 16, 10).c_str());
        eccDomainParams->Gx = Integer(convertBase(StandardCurves::secp256k1.Gx, 16, 10).c_str());
        eccDomainParams->Gy = Integer(convertBase(StandardCurves::secp256k1.Gy, 16, 10).c_str());
        eccDomainParams->n = Integer(convertBase(StandardCurves::secp256k1.n, 16, 10).c_str());
        eccDomainParams->h = Integer(convertBase(StandardCurves::secp256k1.h, 16, 10).c_str());
        eccDomainParams->standardCurveName = StandardCurves::secp256k1.name;
    }
    else if (curveName == "secp192r1")
    {
        eccDomainParams = new ECCDomainParameters();

        eccDomainParams->p = Integer(convertBase(StandardCurves::secp192r1.p, 16, 10).c_str());
        eccDomainParams->a = Integer(convertBase(StandardCurves::secp192r1.a, 16, 10).c_str());
        eccDomainParams->b = Integer(convertBase(StandardCurves::secp192r1.b, 16, 10).c_str());
        eccDomainParams->Gx = Integer(convertBase(StandardCurves::secp192r1.Gx, 16, 10).c_str());
        eccDomainParams->Gy = Integer(convertBase(StandardCurves::secp192r1.Gy, 16, 10).c_str());
        eccDomainParams->n = Integer(convertBase(StandardCurves::secp192r1.n, 16, 10).c_str());
        eccDomainParams->h = Integer(convertBase(StandardCurves::secp192r1.h, 16, 10).c_str());
        eccDomainParams->standardCurveName = StandardCurves::secp192r1.name;
    }

    return eccDomainParams;
}