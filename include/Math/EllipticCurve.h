#ifndef __ELLIPTICCURVE_H__
#define __ELLIPTICCURVE_H__

#include "../Utils/Common.h"
#include "ExtensionField.h"

class EllipticCurve
{
private:

public:
    ExtensionField *eCOverK;
    Integer p, m;
    ELLIPTIC_CURVE_TYPE type;
    PolyElement irredPoly, A, B, C;

    EllipticCurve(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, PolyElement A, PolyElement B, PolyElement C);
    EllipticCurve(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, Integer A, Integer B, Integer C);
    ~EllipticCurve();

    EllipticCurve operator=(const EllipticCurve& e);

    void print();
};

#endif // __ELLIPTICCURVE_H__