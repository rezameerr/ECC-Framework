#include "../../include/Utils/Common.h"
#include "../../include/Math/ExtensionField.h"
#include "../../include/ECC/ECCDomainParameters.h"
#include <iostream>

using namespace std;

ECCDomainParameters::ECCDomainParameters()
{
    
}

ECCDomainParameters::ECCDomainParameters(Integer p, Integer a, Integer b, Integer Gx, Integer Gy, Integer n, Integer h)
{
    this->p = p;
    this->a = a;
    this->b = b;
    this->Gx = Gx;
    this->Gy = Gy;
    this->n = n;
    this->h = h;
    this->standardCurveName = "";
}

ECCDomainParameters::ECCDomainParameters(Integer p, Integer a, Integer b, Integer Gx, Integer Gy, Integer n, Integer h, string standardCurveName)
{
    this->p = p;
    this->a = a;
    this->b = b;
    this->Gx = Gx;
    this->Gy = Gy;
    this->n = n;
    this->h = h;
    this->standardCurveName = standardCurveName;
}

ECCDomainParameters ECCDomainParameters::operator=(const ECCDomainParameters& e)
{
    this->p = e.p;
    this->a = e.a;
    this->b = e.b;
    this->Gx = e.Gx;
    this->Gy = e.Gy;
    this->n = e.n;
    this->h = e.h;
    this->standardCurveName = standardCurveName;
    
    return *this;
}

ECCDomainParameters::~ECCDomainParameters()
{
    
}

void ECCDomainParameters::print()
{
    
}