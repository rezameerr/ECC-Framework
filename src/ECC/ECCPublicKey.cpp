#include "../../include/ECC/ECCPublicKey.h"

ECCPublicKey::ECCPublicKey()
{
    initialiazedDomainParams = false;
}

ECCPublicKey::ECCPublicKey(ECCDomainParameters domainParams)
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

    initialiazedDomainParams = true;
}

ECCPublicKey::~ECCPublicKey()
{
    if (initialiazedDomainParams)
    {
        free(domainParams);
    }
}

ECCDomainParameters ECCPublicKey::getDomainParams()
{
    return *domainParams;
}

void ECCPublicKey::setDomainParams(ECCDomainParameters domainParams)
{
    if (initialiazedDomainParams)
    {
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
}

ECCPublicKey ECCPublicKey::operator=(const ECCPublicKey& e)
{
    this->initialiazedDomainParams = e.initialiazedDomainParams;
    this->domainParams = e.domainParams;   
    this->Q = e.Q;   
     
    return *this;
}