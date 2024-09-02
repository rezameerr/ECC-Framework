#ifndef __ECCDOMAINPARAMETERS_H__
#define __ECCDOMAINPARAMETERS_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"

class ECCDomainParameters
{
private:

public:
    Integer p;
    Integer a;
    Integer b;
    Integer Gx;
    Integer Gy;
    Integer n;
    Integer h;
    string standardCurveName;

    ECCDomainParameters();
    ECCDomainParameters(Integer p, Integer a, Integer b, Integer Gx, Integer Gy, Integer n, Integer h);
    ECCDomainParameters(Integer p, Integer a, Integer b, Integer Gx, Integer Gy, Integer n, Integer h, string standardCurveName);
    ~ECCDomainParameters();

    ECCDomainParameters operator=(const ECCDomainParameters& e);

    void print();
};

#endif // __ECCDOMAINPARAMETERS_H__