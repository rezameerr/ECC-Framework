#ifndef __ECPoint_H__
#define __ECPoint_H__

#include "../Utils/Common.h"

class ECPoint
{
private:
    bool identity;
    PolyElement x, y;

public:
    ECPoint();
    ECPoint(PolyElement x, PolyElement y);
    ECPoint(PolyElement x, PolyElement y, bool identity);
    ECPoint(bool identity);
    ~ECPoint();

    bool getIdentity() const;
    void setIdentity(bool identity);

    PolyElement getX() const;
    void setX(PolyElement x);
    
    PolyElement getY() const;
    void setY(PolyElement y);

    void setXY(PolyElement x, PolyElement y);
    void setXY(PolyElement x, PolyElement y, bool identity);

    ECPoint operator=(const ECPoint& p);
    bool operator==(const ECPoint& p) const;
    bool operator<(const ECPoint& p) const;

    void print();
};

#endif // __ECPoint_H__