#include "../../include/Utils/Common.h"
#include "../../include/Math/ECPoint.h"
#include "../../include/Math/EllipticCurveFq.h"
#include "../../include/ECC/ECCDomainParameters.h"
#include "../../include/ECC/ECC.h"
#include "../../include/ECC/ECCKey.h"

ECCKey::ECCKey()
{
}

ECCKey::ECCKey(Integer d, ECPoint Q)
{
    this->d = d;
    this->Q = Q;
}

ECCKey::~ECCKey()
{
}

Integer ECCKey::getd()
{
    return d;
}

string ECCKey::getd_InBase(int base)
{
    return string(integerToString(d, base));
}

void ECCKey::setd(Integer d)
{
    this->d = d;
}

ECPoint ECCKey::getQ()
{
    return Q;
}


string ECCKey::getQ_X_InBase(ECC *ecc, int base)
{
    Integer x = ecc->E_Fq->elementToInteger(Q.getX(), ecc->domainParams->n);

    return string(integerToString(x, base));
}

string ECCKey::getQ_Y_InBase(ECC *ecc, int base)
{
    Integer y = ecc->E_Fq->elementToInteger(Q.getY(), ecc->domainParams->n);

    return string(integerToString(y, base));
}

void ECCKey::setQ(ECPoint Q)
{
    this->Q = Q;
}

void ECCKey::setdQ(Integer d, ECPoint Q)
{
    this->d = d;
    this->Q = Q;
}

ECCKey ECCKey::operator=(const ECCKey& e)
{
    this->d = e.d;
    this->Q = e.Q;   
     
    return *this;
}