#include "../../include/Utils/Common.h"
#include "../../include/Math/ExtensionField.h"
#include "../../include/Math/ECPoint.h"
#include "../../include/Math/EllipticCurveFq.h"
#include <iostream>

using namespace std;


EllipticCurveFq::EllipticCurveFq(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, PolyElement A, PolyElement B, PolyElement C, Integer d)
{
    eC = new EllipticCurve(p, m, irredPoly, type, A, B, C);
    this->d = d;
    identityECPoint.setIdentity(true);

    if (d == 1) {
        extField = eC->eCOverK;
    } else {
        extField = new ExtensionField(eC->eCOverK->p, d * (eC->eCOverK->m), irredPoly);
    }
}

EllipticCurveFq::EllipticCurveFq(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, Integer A, Integer B, Integer C, Integer d)
{
    eC = new EllipticCurve(p, m, irredPoly, type, A, B, C);
    this->d = d;
    identityECPoint.setIdentity(true);

    if (d == 1) {
        extField = eC->eCOverK;
    } else {
        extField = new ExtensionField(eC->eCOverK->p, d * (eC->eCOverK->m), irredPoly);
    }
}

EllipticCurveFq::EllipticCurveFq(EllipticCurve *eC, Integer d)
{
    this->eC = eC;
    this->d = d;
    identityECPoint.setIdentity(true);

    if (d == 1) {
        extField = eC->eCOverK;
    } else {
        extField = new ExtensionField(eC->eCOverK->p, d * (eC->eCOverK->m), irredPoly);
    }
}

EllipticCurveFq::~EllipticCurveFq()
{
    free(extField);
    free(eC);    
}

EllipticCurveFq EllipticCurveFq::operator=(const EllipticCurveFq& e)
{
    this->p = e.p;
    this->m = e.m;
    this->type = e.type;
    this->irredPoly = e.irredPoly;
    this->eC = e.eC;
    this->extField = e.extField;
    this->A = e.A;
    this->B = e.B;
    this->C = e.C;
    this->d = e.d;
    this->identityECPoint = e.identityECPoint;

    return *this;
}

ECPoint& EllipticCurveFq::add(ECPoint& R, ECPoint& P, ECPoint& Q)
{
    PolyElement x, y, x12;
    PolyElement slope, slopeSquared;
    PolyElement x2m1, y2m1, x1p2, x1m3, slopex1m3, y1pC, x1p2pA, x1p2pApslope, slopex1m3px3;

    if (P.getIdentity() && Q.getIdentity() || isInv(Q, P)) {
        R.setIdentity(true);
        
        return R;
    }

    R.setIdentity(false);

    if (P.getIdentity()) {
        R.setX(Q.getX());
        R.setY(Q.getY());
        
        return R;
    }

    if (Q.getIdentity()) {
        R.setX(P.getX());
        R.setY(P.getY());
        
        return R;
    }

    if (P == Q) {
        return dbl(R, P);
    }

    extField->sub(y2m1, Q.getY(), P.getY());
    extField->sub(x2m1, Q.getX(), P.getX());
    extField->div(slope, y2m1, x2m1);
    extField->sqr(slopeSquared, slope);
    extField->add(x1p2, P.getX(), Q.getX());

    switch (eC->type)
    {
        case ELLIPTIC_CURVE_TYPE::E_K:
            extField->sub(x, slopeSquared, x1p2);
            extField->sub(x1m3, P.getX(), x);
            extField->mul(slopex1m3, slope, x1m3);
            extField->sub(y, slopex1m3, P.getY());

            R.setXY(x, y);
            return R;
        
        case ELLIPTIC_CURVE_TYPE::NON_SUPERSINGULAR:
            extField->add(x1p2pA, x1p2, eC->A);
            extField->add(x1p2pApslope, x1p2pA, slope);
            extField->add(x, x1p2pApslope, slopeSquared);
            extField->add(x1m3, P.getX(), x);
            extField->mul(slopex1m3, slope, x1m3);
            extField->add(slopex1m3px3, slopex1m3, x);
            extField->add(y, slopex1m3px3, P.getY());

            R.setXY(x, y);
            return R;
            
        case ELLIPTIC_CURVE_TYPE::SUPERSINGULAR:
            extField->add(x, slopeSquared, x1p2);
            extField->add(x1m3, P.getX(), x);
            extField->mul(slopex1m3, slope, x1m3);
            extField->add(y1pC, P.getY(), eC->C);
            extField->add(y, y1pC, slopex1m3);

            R.setXY(x, y);
            return R;
    }

    return R;
}

ECPoint& EllipticCurveFq::dbl(ECPoint& R, ECPoint& P)
{
    PolyElement x, y, x12;
    PolyElement slope, slopeSquared;
    PolyElement _3x12, _2y, _3x12pA, _2x, _x, slope_x;
    PolyElement xpy, Bdx12, slopex, slopex_x;
    PolyElement x12pA, ypC, xpx, slopexpx;

    extField->sqr(x12, P.getX());

    switch (eC->type)
    {
        case ELLIPTIC_CURVE_TYPE::E_K:
            extField->scalarMul(_3x12, x12, 3);
            extField->scalarMul(_2y, P.getY(), 2);
            extField->add(_3x12pA, _3x12, eC->A);
            extField->div(slope, _3x12pA, _2y);
            extField->sqr(slopeSquared, slope);
            extField->scalarMul(_2x, P.getX(), 2);
            extField->sub(x, slopeSquared, _2x);
            extField->sub(_x, P.getX(), x);
            extField->sub(y, extField->mul(slope_x, slope, _x), P.getY());

            R.setXY(x, y);
            return R;
        
        case ELLIPTIC_CURVE_TYPE::NON_SUPERSINGULAR:
            extField->add(xpy, x12, P.getY());
            extField->div(slope, xpy, P.getX());
            extField->div(Bdx12, eC->B, x12);
            extField->add(x, x12, Bdx12);
            extField->mul(slopex, slope, x);
            extField->add(slopex_x, slopex, x);
            extField->add(y, x12, slopex_x);

            R.setXY(x, y);
            return R;
            
        case ELLIPTIC_CURVE_TYPE::SUPERSINGULAR:
            extField->add(x12pA, x12, eC->A);
            extField->div(slope, x12pA, eC->C);
            extField->sqr(slopeSquared, slope);
            x = slopeSquared;
            extField->add(ypC, P.getY(), eC->C);
            extField->add(xpx, P.getX(), x);
            extField->mul(slopexpx, xpx, slope);
            extField->add(y, ypC, slopexpx);

            R.setXY(x, y);
            return R;
    }

    return R;
}

ECPoint& EllipticCurveFq::scalarMul(ECPoint& R, ECPoint& P, Integer k, Integer order)
{
    if (P.getIdentity()) {
        R.setIdentity(true);

        return R;
    }

    ECPoint tmp(false);
    ECPoint i(P);

    R.setIdentity(true);

    if (order > 0) {
        k %= order;
    }

    while (k > 0)
    {
        if (k % 2) {
            add(tmp, R, i);
            R = tmp;
        }
        dbl(tmp, i);
        i = tmp;
        k /= 2;
    }
    
    return R;
}

const ECPoint& EllipticCurveFq::inv(ECPoint& Q, const ECPoint& P)
{
    if (P.getIdentity()) {
        Q.setIdentity(true);

        return Q;
    }

    Q.setIdentity(false);
    PolyElement temp;

    switch (eC->type)
    {
        case ELLIPTIC_CURVE_TYPE::E_K:
            Q.setX(P.getX());
            temp = Q.getY();
            extField->additiveInv(temp, P.getY()); 
            Q.setY(temp);
            return Q;
        
        case ELLIPTIC_CURVE_TYPE::NON_SUPERSINGULAR:
            Q.setX(P.getX());
            temp = Q.getY();
            extField->add(temp, P.getY(), P.getX());
            Q.setY(temp);
            return Q;
            
        case ELLIPTIC_CURVE_TYPE::SUPERSINGULAR:
            Q.setX(P.getX());
            temp = Q.getY();
            extField->add(temp, P.getY(), eC->C);
            Q.setY(temp);
            return Q;
        
        default:
            return Q;
    }
}

bool EllipticCurveFq::isInv(const ECPoint& Q, const ECPoint& P)
{
    ECPoint R;

    inv(R, P);

    return (R == Q);
}

bool EllipticCurveFq::verifyECPoint(const ECPoint& P) const
{
    if (P.getIdentity()) {
        return true;
    }

    PolyElement rhs, lhs, y2, x2, x3, Ax2, Ax, xy, Cy;

    extField->sqr(x2, P.getX());
    extField->sqr(y2, P.getY());
    extField->mul(x3, x2, P.getX());

    lhs = y2;
    rhs = x3;

    switch (eC->type)
    {
        case ELLIPTIC_CURVE_TYPE::E_K:
            extField->mul(Ax, eC->A, P.getX());
            extField->addin(rhs, Ax);
            extField->addin(rhs, eC->B);
            break;
        
        case ELLIPTIC_CURVE_TYPE::NON_SUPERSINGULAR:
            extField->mul(xy, P.getX(), P.getY());
            extField->addin(lhs, xy);

            extField->mul(Ax2, eC->A, x2);
            extField->addin(rhs, Ax2);
            extField->addin(rhs, eC->B);
            break;
            
        case ELLIPTIC_CURVE_TYPE::SUPERSINGULAR:
            extField->mul(Cy, eC->C, P.getY());
            extField->addin(lhs, Cy);

            extField->mul(Ax, eC->A, P.getX());
            extField->addin(rhs, Ax);
            extField->addin(rhs, eC->B);
            break;
    }

    return (lhs == rhs);
}

Integer EllipticCurveFq::elementToInteger(PolyElement element, Integer eccModulus)
{
    Integer result = 0;
    PolyElement tmp;
    
    if (element.size())
    {
        extField->Fp_X.assign(tmp, element);
        extField->Fp_X.setdegree(tmp);

        for (Integer i = 0; i < tmp.size(); i++)
        {
            result += tmp[i] * (i + 1);
            result %= eccModulus;
        } 
    }

    return result;
}

void EllipticCurveFq::print()
{
    cout << "Elliptic Curve defined by " << endl;

    switch (eC->type)
    {
        case ELLIPTIC_CURVE_TYPE::E_K:
            cout << "y^2 = x^3 + " << eC->A.at(0) << "x + " << eC->B.at(0);
            break;
        
        case ELLIPTIC_CURVE_TYPE::NON_SUPERSINGULAR:
            cout << "y^2 + xy = x^3 + " << eC->A.at(0) << "x^2 + " << eC->B.at(0);
            break;
            
        case ELLIPTIC_CURVE_TYPE::SUPERSINGULAR:
            cout << "y^2 + " << eC->C.at(0) << "y = x^3 + " << eC->A.at(0) << "x + " << eC->B.at(0);
            break;
    }

    cout << endl;
    cout << " over prime field in X of size " << eC->p << "^" << eC->m 
        << " with irreducible polynomial of ";
    eC->eCOverK->Fp_X.write(cout << "", eC->irredPoly);
    cout << endl;
}