#include "../../include/Utils/Common.h"
#include "../../include/Math/ExtensionField.h"
#include "../../include/Math/ECPoint.h"
#include <iostream>

using namespace std;

ECPoint::ECPoint()
{
    this->identity = false;
}

ECPoint::ECPoint(PolyElement x, PolyElement y)
{
    this->x = x;
    this->y = y;
    this->identity = false;
}

ECPoint::ECPoint(PolyElement x, PolyElement y, bool identity)
{
    this->x = x;
    this->y = y;
    this->identity = identity;
}

ECPoint::ECPoint(bool identity)
{
    this->identity = identity;
}

ECPoint::~ECPoint()
{
    
}

bool ECPoint::getIdentity() const
{
    return identity;
}

void ECPoint::setIdentity(bool identity)
{
    this->identity = identity;
}

PolyElement ECPoint::getX() const
{
    return x;
}

void ECPoint::setX(PolyElement x)
{
    this->x = x;
}

PolyElement ECPoint::getY() const
{
    return y;
}

void ECPoint::setY(PolyElement y)
{
    this->y = y;
}

void ECPoint::setXY(PolyElement x, PolyElement y)
{
    this->x = x;
    this->y = y;
    identity = false;
}

void ECPoint::setXY(PolyElement x, PolyElement y, bool identity)
{
    this->x = x;
    this->y = y;
    this->identity = identity;
}

ECPoint ECPoint::operator =(const ECPoint& p)
{
    if (p.identity) {
        this->identity = true;
        return *this;
    }

    this->x = p.x;
    this->y = p.y;
    this->identity = p.identity;

    return *this;
}

bool ECPoint::operator ==(const ECPoint& p) const
{
    return (this->identity && p.identity) || 
        (!this->identity && !p.identity && this->x == p.x && this->y == p.y);
}

bool ECPoint::operator<(const ECPoint& p) const
{
    return this->identity ? !p.identity : 
        (!p.identity && (this->x < p.x || (this->x == p.x && this->y < p.y)));
}

void ECPoint::print()
{
    cout << "(" << x.at(0) << ", "<< y.at(0) << ")";

    if (identity) {
        cout << " : (INFINITY)";
    }

    cout << endl;
}

