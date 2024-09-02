#ifndef __ELLIPTICCURVEFQ_H__
#define __ELLIPTICCURVEFQ_H__

#include "../Utils/Common.h"
#include "ExtensionField.h"
#include "ECPoint.h"
#include "EllipticCurve.h"

class EllipticCurveFq
{
private:
    
public:
    ExtensionField *extField;
    EllipticCurve *eC;
    ECPoint identityECPoint;
    Integer p, m;
    ELLIPTIC_CURVE_TYPE type;
    PolyElement irredPoly, A, B, C;
    Integer d; // E(Fq^d)

    EllipticCurveFq(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, PolyElement A, PolyElement B, PolyElement C, Integer d);
    EllipticCurveFq(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, Integer A, Integer B, Integer C, Integer d);
    EllipticCurveFq(EllipticCurve *eC, Integer d);
    ~EllipticCurveFq();

    EllipticCurveFq operator=(const EllipticCurveFq& e);
    
    ECPoint& add(ECPoint& R, ECPoint& P, ECPoint& Q);
    ECPoint& dbl(ECPoint& R, ECPoint& P);
    ECPoint& scalarMul(ECPoint& R, ECPoint& P, Integer k, Integer order);
    const ECPoint& inv(ECPoint& Q, const ECPoint& P);
    bool isInv(const ECPoint& Q, const ECPoint& P);
    bool verifyECPoint(const ECPoint& P) const;

    Integer elementToInteger(PolyElement element, Integer eccModulus); // eccModulus = ECCDomainParameters->n

    void print();
};

#endif // __ELLIPTICCURVEFQ_H__