#include "../../include/Utils/Common.h"
#include "../../include/Math/ExtensionField.h"
#include <iostream>

using namespace std;
using namespace Givaro;

ExtensionField::ExtensionField(Integer p)
{
    this->p = p;
    this->m = 1;

    /*
    Fp = new PrimeField((PrimeField::Residu_t)p);
    Fp_X = new Poly1Dom<PrimeField, Dense>(Fp, Indeter("X"));
    */

    Fp = PrimeField((PrimeField::Residu_t)p);
    Fp_X = Poly1Dom<PrimeField, Dense>(Fp, Indeter("X"));

    /*
    Fp_X->assign(irredPoly, p);
    Fp_X.zassign(zero, Fp_X.zero);
    Fp_X.assign(one, Fp_X.one);
    Fp_X.assign(mOne, Fp_X.mOne);
    */

    Fp_X.assign(irredPoly, p);
    Fp_X.assign(zero, Fp_X.zero);
    Fp_X.assign(one, Fp_X.one);
    Fp_X.assign(mOne, Fp_X.mOne);
}

ExtensionField::ExtensionField(Integer p, Integer m, PolyElement irredPoly)
{
    this->p = p;
    this->m = m;

    /*
    Fp = new PrimeField((PrimeField::Residu_t)p);
    Fp_X = new Poly1Dom<PrimeField, Dense>(Fp, Indeter("X"));

    Fp_X->assign(this->irredPoly, irredPoly);
    Fp_X->assign(zero, Fp_X->zero);
    Fp_X->assign(one, Fp_X->one);
    Fp_X->assign(mOne, Fp_X->mOne);
    */

    Fp = PrimeField((PrimeField::Residu_t)p);
    Fp_X = Poly1Dom<PrimeField, Dense>(Fp, Indeter("X"));

    Fp_X.assign(this->irredPoly, irredPoly);
    Fp_X.assign(zero, Fp_X.zero);
    Fp_X.assign(one, Fp_X.one);
    Fp_X.assign(mOne, Fp_X.mOne);
}

ExtensionField::~ExtensionField()
{
    /*
    free(Fp);
    free(Fp_X);
    */
}

ExtensionField ExtensionField::operator=(const ExtensionField &e)
{
    p = e.p;
    m = e.m;
    Fp = e.Fp;
    Fp_X = e.Fp_X;
    irredPoly = e.irredPoly;
    zero = e.zero;
    one = e.one;
    mOne = e.mOne;

    return *this;
}

PolyElement& ExtensionField::neg(PolyElement& r, const PolyElement& a) const
{
    Fp_X.neg(r, a);

    return r;
}

PolyElement& ExtensionField::addin(PolyElement& r, const PolyElement& a) const
{
    Fp_X.addin(r, a);

    return r;
}

PolyElement& ExtensionField::add(PolyElement& r, const PolyElement& a, const PolyElement& b) const
{
    Fp_X.add(r, a, b);

    return r;
}

PolyElement& ExtensionField::sub(PolyElement& r, const PolyElement& a, const PolyElement& b) const
{
    Fp_X.sub(r, a, b);

    return r;
}

PolyElement& ExtensionField::mul(PolyElement& r, const PolyElement& a, const PolyElement& b) const
{
    if (m == 1) {
        Fp_X.mul(r, a, b);
    } else {
        PolyElement tmp, q;
        Fp_X.mul(tmp, a, b);
        Fp_X.divmod(q, r, tmp, irredPoly);
    }

    return r;
}

PolyElement& ExtensionField::mulin(PolyElement& r, const PolyElement& a) const
{
    if (m == 1) {
        Fp_X.mulin(r, a);
    } else {
        PolyElement tmp, q;
        Fp_X.mulin(tmp, a);
        Fp_X.divmod(q, r, tmp, irredPoly);
    }

    return r;
}

PolyElement& ExtensionField::div(PolyElement& q, const PolyElement& a, const PolyElement& b) const
{
    PolyElement i;
    
    inv(i, b);
    mul(q, a, i);

    return q;
}

PolyElement& ExtensionField::sqr(PolyElement& r, const PolyElement& a) const
{
    if (m == 1) {
        Fp_X.sqr(r, a);
    } else {
        PolyElement tmp, q;
        Fp_X.sqr(tmp, a);
        Fp_X.divmod(q, r, tmp, irredPoly);
    }

    return r;
}

PolyElement& ExtensionField::inv(PolyElement& i, const PolyElement& a) const
{
    PolyElement dummy, d;

    d = Fp_X.gcd(d, i, dummy, a, irredPoly);

    if (Fp_X.isOne(d)) {
        return i;
    }

    Fp_X.assign(i, Fp_X.zero);

    return i;
}

PolyElement& ExtensionField::additiveInv(PolyElement& i, const PolyElement& a) const
{
    Fp_X.sub(i, Fp_X.zero, a);

    return i;
}

PolyElement& ExtensionField::scalarMul(PolyElement& r, const PolyElement& a, Integer k) const
{
    if (k > p) {
        k %= p;
    }

    if (m == 1) {
        PolyElement polyElementK;
        PrimeField::Element tmp;

        Fp_X.assign(polyElementK, Fp.init(tmp, k));
        Fp_X.mul(r, a, polyElementK);       
    } else {
        PolyElement tmp, i;

        i = a;
        Fp_X.assign(r, zero);

        while (k > 0)
        {
            if (k % 2) {
                Fp_X.addin(r, i);
            }

            i = Fp_X.add(tmp, i, i);
            k /= 2;
        }     
    }

    return r;
}

bool ExtensionField::isPolyElement(const PolyElement& a)
{
    if (Fp_X.degree(a)._deg < m) {
        return true;
    }

    return false;
}

void ExtensionField::printPolyElement(const PolyElement& a)
{
    Fp_X.write(cout << "", a);
}