#ifndef __HASHFUNCTIONS_H__
#define __HASHFUNCTIONS_H__

#include <string>

using namespace std;

class HashFunctions
{
private:

public:
    HashFunctions();
    ~HashFunctions();

    static string getHash(const string &input, string hashFunctionName, string format);
    static unsigned char* getHash(unsigned char *input, size_t inputLength, string hashFunctionName);
};



#endif // __HASHFUNCTIONS_H__