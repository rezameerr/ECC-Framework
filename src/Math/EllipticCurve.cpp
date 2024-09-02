#include "../../include/Utils/Common.h"
#include "../../include/Math/ExtensionField.h"
#include "../../include/Math/ECPoint.h"
#include "../../include/Math/EllipticCurve.h"
#include <iostream>

using namespace std;

EllipticCurve::EllipticCurve(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, PolyElement A, PolyElement B, PolyElement C)
{
    this->p = p;
    this->m = m;
    this->type = type;
    this->eCOverK = new ExtensionField(p, m, irredPoly);
    this->eCOverK->Fp_X.assign(this->A, A);
    this->eCOverK->Fp_X.assign(this->B, B);

    if (type == ELLIPTIC_CURVE_TYPE::SUPERSINGULAR) {
        this->eCOverK->Fp_X.assign(this->C, C);
    }
}

EllipticCurve::EllipticCurve(Integer p, Integer m, PolyElement irredPoly, ELLIPTIC_CURVE_TYPE type, Integer A, Integer B, Integer C)
{
    this->p = p;
    this->m = m;
    this->type = type;
    this->eCOverK = new ExtensionField(p, m, irredPoly);
    this->eCOverK->Fp_X.assign(this->A, A);
    this->eCOverK->Fp_X.assign(this->B, B);

    if (type == ELLIPTIC_CURVE_TYPE::SUPERSINGULAR) {
        this->eCOverK->Fp_X.assign(this->C, C);
    }

}

EllipticCurve::~EllipticCurve()
{
    free(eCOverK);
}

EllipticCurve EllipticCurve::operator=(const EllipticCurve& e)
{
    this->p = e.p;
    this->m = e.m;
    this->type = e.type;
    this->irredPoly = e.irredPoly;
    this->eCOverK = e.eCOverK;
    this->A = e.A;
    this->B = e.B;
    this->C = e.C;

    return *this;
}

void EllipticCurve::print()
{
    
}
