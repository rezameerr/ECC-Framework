#include "../../include/ECC/ECCPrivateKey.h"

ECCPrivateKey::ECCPrivateKey(/* args */)
{
}

ECCPrivateKey::~ECCPrivateKey()
{
}

ECCPrivateKey ECCPrivateKey::operator=(const ECCPrivateKey& e)
{
    this->d = e.d;   
     
    return *this;
}