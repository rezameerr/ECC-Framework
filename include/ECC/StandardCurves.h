#ifndef __STANDARDCURVES_H__
#define __STANDARDCURVES_H__

#include "../Utils/Common.h"
#include "../Math/ECPoint.h"
#include "ECCDomainParameters.h"
#include <string>

using namespace std;

/*
struct secp192r1
{
    string name = "secp192r1";

    string p = "fffffffffffffffffffffffffffffffeffffffffffffffff";
    string a = "fffffffffffffffffffffffffffffffefffffffffffffffc";
    string b = "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1";
    string Gx = "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012";
    string Gy = "07192b95ffc8da78631011ed6b24cdd573f977a11e794811";
    string n = "ffffffffffffffffffffffff99def836146bc9b1b4d22831";
    string h = "1";
};
*/

class StandardCurves
{
private:

public:
    struct StandardCurve
    {
        string name;
        string p;
        string a;
        string b;
        string Gx;
        string Gy;
        string n;
        string h;
    };

    StandardCurves();
    ~StandardCurves();

    static ECCDomainParameters* getECCDomainParametersByStandardCurveName(string curveName);

    static StandardCurve secp256k1;
    static StandardCurve secp192r1;
};

#endif // __STANDARDCURVES_H__