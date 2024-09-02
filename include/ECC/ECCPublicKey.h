#ifndef __ECCPUBLICKEY_H__
#define __ECCPUBLICKEY_H__

#include "../Math/ECPoint.h"
#include "ECCDomainParameters.h"

class ECCPublicKey
{
private:
    bool initialiazedDomainParams;
    ECCDomainParameters *domainParams;

public:
    ECPoint Q;

    ECCPublicKey();
    ECCPublicKey(ECCDomainParameters domainParams);
    ~ECCPublicKey();

    ECCDomainParameters getDomainParams();
    void setDomainParams(ECCDomainParameters domainParams);

    ECCPublicKey operator=(const ECCPublicKey& e);
};

#endif // __ECCPUBLICKEY_H__