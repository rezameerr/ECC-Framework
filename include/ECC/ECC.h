#ifndef __ECC_H__
#define __ECC_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "../Math/EllipticCurveFq.h"
#include "ECCDomainParameters.h"
#include "ECCKey.h"
#include "ECCPublicKey.h"

class ECC
{
private:
    bool initialiazed;
    ECCDomainParameters *domainParams;

public:
    EllipticCurveFq *E_Fq;
    ECPoint G;

    ECC();
    ECC(ECCDomainParameters domainParams);
    ~ECC();

    ECCDomainParameters getDomainParams();
    void setDomainParams(ECCDomainParameters domainParams);

    Integer generateSecureRandomIntegerOverE_Fq();
    ECCKey generateKeyPair();
    bool validatePublicKey(ECPoint Q); // Q should be a valid elliptic curve point. It's not about verifying authenticity of public key. For authenticity verification, other mechanisms are required, such as certificate, etc.
    bool validatePublicKey(ECCPublicKey eccPublicKey);
    
    ECC operator=(const ECC& e);

    void print();

    friend class ECCKey;
    friend class ECDHE;
    friend class ECDSA;
    friend class ECElGamal;
};

#endif // __ECC_H__