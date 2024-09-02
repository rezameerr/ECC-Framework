#ifndef __COMMON_H__
#define __COMMON_H__

#include <givaro/modular-integer.h>
#include <givaro/givpoly1.h>
#include <bits/stdc++.h>

using namespace std;
using namespace Givaro;

typedef Modular<Integer> PrimeField; // Fp or Z/pZ or GF(p) typedef
typedef Poly1Dom<PrimeField, Dense>::Element PolyElement;
typedef PrimeField::Element PrimeFieldElement;

enum ELLIPTIC_CURVE_TYPE {
    E_K = 0,
    NON_SUPERSINGULAR,
    SUPERSINGULAR
};

void stringToLowercase(string& input);
void stringToLowercase(string& input, char *ret);
void stringToUppercase(string& input);
void stringToUppercase(string& input, char *ret);
string integerToString(Integer input);
char* integerToString(Integer input, int base);
char* integerToStringUsingGMP(Integer input);
void integerToStringUsingGMP(Integer input, char *ret);
Integer stringToInteger(char *input);
Integer stringToInteger(char *input, int base);
uint8_t* hexToByteArray(string input);
uint8_t* hexToByteArray(char *input);
void hexToByteArray(const char *input, uint8_t *output);
string byteArrayToHexString(uint8_t *input, int len);
char* byteArrayToHex(uint8_t *input, int len);
unsigned char* byteArrayToString(uint8_t *input, int len);
char* charArrayToLowercase(const char *input);
char* charArrayToUppercase(const char *input);
unsigned char* secureRandomUsingOpenSSL(size_t length);
char* secureRandomUsingOpenSSLHex(size_t length);
char* secureRandomUsingOpenSSLBase64(size_t length);

/*-------------- Below code is from: https://www.geeksforgeeks.org/convert-a-number-from-base-a-to-base-b/ ----------*/
// Original code by user: maddler
// User profile: https://www.geeksforgeeks.org/user/maddler/
/*-------------------------------------------------------------------------*/
//-------------------------- Code is modified -------------------------------------------------------
// C++ program for the above approach

// Function to return ASCII
// value of a character
int val(char c);

// Function to convert a number
// from given base to decimal number
Integer convertToDecimal(string str, int base);

// Function to return equivalent
// character of a given value
char reVal(int num);

// Function to convert a given
// decimal number to a given base
string convertFromDecimal(Integer input, int base);

// Function to convert a given number
// from a base to another base
string convertBase(string input, int fromBase, int toBase);
/*-------------- [END]: Above code is from: https://www.geeksforgeeks.org/convert-a-number-from-base-a-to-base-b/ ----------*/




//
//
//
//
//
//
//
//



/*-------------- Below code is from: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c ----------*/
// Original code by user: ryyst
// User profile: https://stackoverflow.com/users/282635/ryyst
/*-------------------------------------------------------------------------*/
char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void build_decoding_table();

void base64_cleanup();
/*-------------- [END]: Above code is from: https://www.geeksforgeeks.org/convert-a-number-from-base-a-to-base-b/ ----------*/

#endif // __COMMON_H__