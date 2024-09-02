#include "../../include/Utils/Common.h"
#include "../../include/Math/ECPoint.h"
#include "../../include/Math/EllipticCurveFq.h"
#include "../../include/ECC/ECCDomainParameters.h"
#include "../../include/ECC/ECC.h"

ECC::ECC()
{
    initialiazed = false;
}

ECC::ECC(ECCDomainParameters domainParams)
{
    this->domainParams = new ECCDomainParameters();

    this->domainParams->p = domainParams.p;
    this->domainParams->a = domainParams.a;
    this->domainParams->b = domainParams.b;
    this->domainParams->Gx = domainParams.Gx;
    this->domainParams->Gy = domainParams.Gy;
    this->domainParams->n = domainParams.n;
    this->domainParams->h = domainParams.h;
    this->domainParams->standardCurveName = domainParams.standardCurveName;

    PolyElement x, y, dummy;

    E_Fq = new EllipticCurveFq(this->domainParams->p, Integer("1"), dummy, ELLIPTIC_CURVE_TYPE::E_K, 
                                        this->domainParams->a, this->domainParams->b, Integer("1"), 
                                        Integer("1"));

    E_Fq->extField->Fp_X.assign(x, this->domainParams->Gx);
    E_Fq->extField->Fp_X.assign(y, this->domainParams->Gy);

    G.setXY(x, y);

    initialiazed = true;
}

ECC::~ECC()
{
    if (initialiazed)
    {
        free(E_Fq);
        free(domainParams);
    }
}

ECCDomainParameters ECC::getDomainParams()
{
    return *domainParams;
}

void ECC::setDomainParams(ECCDomainParameters domainParams)
{
    if (initialiazed)
    {
        free(E_Fq);
        free(this->domainParams);
    }

    this->domainParams = new ECCDomainParameters();

    this->domainParams->p = domainParams.p;
    this->domainParams->a = domainParams.a;
    this->domainParams->b = domainParams.b;
    this->domainParams->Gx = domainParams.Gx;
    this->domainParams->Gy = domainParams.Gy;
    this->domainParams->n = domainParams.n;
    this->domainParams->h = domainParams.h;
    this->domainParams->standardCurveName = domainParams.standardCurveName;

    PolyElement x, y, dummy;

    this->E_Fq = new EllipticCurveFq(this->domainParams->p, Integer("1"), dummy, ELLIPTIC_CURVE_TYPE::E_K, 
                                        this->domainParams->a, this->domainParams->b, Integer("1"), 
                                        Integer("1"));
    
    E_Fq->extField->Fp_X.assign(x, this->domainParams->Gx);
    E_Fq->extField->Fp_X.assign(y, this->domainParams->Gy);

    G.setXY(x, y);
}

ECCKey ECC::generateKeyPair()
{
    Integer d;
    ECPoint Q;
    ECCKey eccKey;

    d = generateSecureRandomIntegerOverE_Fq();
    E_Fq->scalarMul(Q, G, d, domainParams->n);

    eccKey.setdQ(d, Q);

    return eccKey;
}

Integer ECC::generateSecureRandomIntegerOverE_Fq()
{
    Integer secureRand;

    GivRandom generator;
    Integer::seeding(generator.seed());
    Integer::random_lessthan(secureRand, domainParams->n); // TO-DO: Using true cryptographic grade RNG in the future, RNG should be truly random and secure.

    return secureRand;
}

bool ECC::validatePublicKey(ECPoint Q)
{
    if (Q.getIdentity())
    {
        return false;
    }

    if (!E_Fq->extField->isPolyElement(Q.getX()) || 
        !E_Fq->extField->isPolyElement(Q.getY()))
    {
        return false;
    }

    if (!E_Fq->verifyECPoint(Q))
    {
        return false;
    }

    ECPoint r;
    //r.setIdentity(false);

    E_Fq->scalarMul(r, Q, domainParams->n, domainParams->n);

    if (!r.getIdentity())
    {
        return false;
    }

    return true;
}

bool ECC::validatePublicKey(ECCPublicKey eccPublicKey)
{
    return validatePublicKey(eccPublicKey.Q);
}

ECC ECC::operator=(const ECC& e)
{
    this->domainParams = e.domainParams;
    this->G = e.G;
    this->E_Fq = e.E_Fq;
    this->initialiazed = e.initialiazed;
    
    return *this;
}

void ECC::print()
{
    cout << endl 
    << "ECC Domain Parameters: " << endl
    << "Standard Curve Name: " << domainParams->standardCurveName << endl
    << "p = 0x" << convertBase(integerToString(domainParams->p), 10, 16) << endl
    << "a = 0x" << convertBase(integerToString(domainParams->a), 10, 16) << endl
    << "b = 0x" << convertBase(integerToString(domainParams->b), 10, 16) << endl
    << "G = (0x" << convertBase(integerToString(domainParams->Gx), 10, 16) << ", " << endl
    << "    0x" << convertBase(integerToString(domainParams->Gy), 10, 16) << ")" << endl
    << "n = 0x" << convertBase(integerToString(domainParams->n), 10, 16) << endl
    << "h = 0x" << convertBase(integerToString(domainParams->h), 10, 16) << endl;
}
