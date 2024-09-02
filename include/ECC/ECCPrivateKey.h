#ifndef __ECCPRIVATEKEY_H__
#define __ECCPRIVATEKEY_H__

#include "../Utils/Common.h"

class ECCPrivateKey
{
private:

public:
    Integer d;

    ECCPrivateKey();
    ~ECCPrivateKey();

    ECCPrivateKey operator=(const ECCPrivateKey& e);
};

#endif // __ECCPRIVATEKEY_H__