#ifndef __ECCKEY_H__
#define __ECCKEY_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "../Math/EllipticCurveFq.h"
#include "ECCDomainParameters.h"
#include "ECC.h"

class ECC;

class ECCKey
{
private:
    Integer d; // Private Key
    ECPoint Q; // Public Key: Q = dp = dG
    
public:
    ECCKey();
    ECCKey(Integer d, ECPoint Q);
    ~ECCKey();

    Integer getd();
    string getd_InBase(int base);
    void setd(Integer d);

    ECPoint getQ();
    string getQ_X_InBase(ECC *ecc, int base);
    string getQ_Y_InBase(ECC *ecc, int base);
    void setQ(ECPoint Q);
    void setdQ(Integer d, ECPoint Q);

    ECCKey operator=(const ECCKey& e);
};

#endif // __ECCKEY_H__