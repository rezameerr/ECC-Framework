#ifndef __EXTENSIONFIELD_H__
#define __EXTENSIONFIELD_H__

#include <givaro/modular-integer.h>
#include <givaro/givpoly1.h>
#include "../Utils/Common.h"

using namespace Givaro;

class ExtensionField
{
private:

public:
    Integer p, m;  // p: Prime number
    PrimeField Fp; // Prime Field of Order q=p^m - Fp - Z/pZ - GF(p^m)
    // PrimeField *Fp;                     // Prime Field of Order q=p^m - Fp - Z/pZ - GF(p^m)
    Poly1Dom<PrimeField, Dense> Fp_X; // Polynomials over GF(p^m) with X as indeterminate
    // Poly1Dom<PrimeField, Dense> *Fp_X;  // Polynomials over GF(p^m) with X as indeterminate
    PolyElement irredPoly, zero, one, mOne; // Irreducible polynomial f(x) over GF(p^m) with degree m
    ExtensionField(Integer p);
    ExtensionField(Integer p, Integer m, PolyElement irredPoly);
    ~ExtensionField();

    ExtensionField operator=(const ExtensionField& e);

    PolyElement& neg(PolyElement& r, const PolyElement& a) const;
    PolyElement& addin(PolyElement& r, const PolyElement& a) const;
    PolyElement& add(PolyElement& r, const PolyElement& a, const PolyElement& b) const;
    PolyElement& sub(PolyElement& r, const PolyElement& a, const PolyElement& b) const;
    PolyElement& mul(PolyElement& r, const PolyElement& a, const PolyElement& b) const;
    PolyElement& mulin(PolyElement& r, const PolyElement& a) const;
    PolyElement& div(PolyElement& q, const PolyElement& a, const PolyElement& b) const;
    PolyElement& sqr(PolyElement& r, const PolyElement& a) const;
    PolyElement& inv(PolyElement& i, const PolyElement& a) const;
    PolyElement& additiveInv(PolyElement& i, const PolyElement& a) const;
    PolyElement& scalarMul(PolyElement& r, const PolyElement& a, Integer k) const;

    bool isPolyElement(const PolyElement& a);

    void printPolyElement(const PolyElement& a);
};

#endif // __EXTENSIONFIELD_H__