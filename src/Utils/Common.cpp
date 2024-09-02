#include "../../include/Utils/Common.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/rand.h>

using namespace std;
using namespace Givaro;

void stringToLowercase(string& input)
{
	transform(input.begin(), input.end(), input.begin(),
		[](unsigned char c){ return tolower(c); });
}

void stringToUppercase(string& input)
{
	transform(input.begin(), input.end(), input.begin(),
		[](unsigned char c){ return toupper(c); });
}

string integerToString(Integer input)
{
	stringstream ss(stringstream::out | stringstream::binary);
    ss << input;

	return ss.str();
}

void stringToLowercase(string& input, char *ret)
{
	transform(input.begin(), input.end(), input.begin(),
		[](unsigned char c){ return tolower(c); });

	const char *temp = input.c_str();
	memcpy(ret, temp, strlen(temp));
}

void stringToUppercase(string& input, char *ret)
{
	transform(input.begin(), input.end(), input.begin(),
		[](unsigned char c){ return toupper(c); });

	const char *temp = input.c_str();
	memcpy(ret, temp, strlen(temp));
}

char* charArrayToLowercase(const char *input)
{
	int len = strlen(input);
	char *output = (char*)malloc((len + 1) * sizeof(char));
	memset(output, 0, len + 1);

	for(int i = 0; i < len; i++)
	{
  		output[i] = tolower(input[i]);
	}

	return output;
}

char* charArrayToUppercase(const char *input)
{
	int len = strlen(input);
	char *output = (char*)malloc((len + 1) * sizeof(char));
	memset(output, 0, len + 1);

	for(int i = 0; i < len; i++)
	{
  		output[i] = toupper(input[i]);
	}

	return output;
}

void integerToStringUsingGMP(Integer input, char *ret)
{
	int len = Givaro::length(input);
	ret = (char*)malloc(len * sizeof(char));
	mpz_get_str(ret, 10, input.get_mpz());
}

char* integerToStringUsingGMP(Integer input)
{
	int size = Givaro::length(input);
	char *temp = (char*)malloc(size * sizeof(char));
	mpz_get_str(temp, 10, input.get_mpz());

	return temp;
}

char* integerToString(Integer input, int base)
{
	int size = input.size_in_base(base);
	char *temp = (char*)malloc(size * sizeof(char));
	mpz_get_str(temp, base, input.get_mpz());

	temp = charArrayToUppercase(temp);

	return temp;
}

Integer stringToInteger(char *input)
{
	input = charArrayToUppercase(input);
	mpz_class mpzClass(input, 16);
	Integer ret = Integer(mpzClass);

	return ret;
}

Integer stringToInteger(char *input, int base)
{
	input = charArrayToUppercase(input);
	mpz_class mpzClass(input, base);
	Integer ret = Integer(mpzClass);

	return ret;
}

uint8_t* hexToByteArray(string input)
{
	stringToUppercase(input);

	uint8_t *output;

	if (input.length() % 2 != 0)
	{
		input = "0" + input;
	}

	int len = input.length();

	output = (uint8_t*)malloc((len / 2) * sizeof(uint8_t));
	memset(output, 0, len / 2);

    for (int i = 0; i < len; i += 2)
  	{
    	uint8_t t = val(input[i]) << 4;
        t += val(input[i + 1]);

    	output[i / 2] = t;
  	}

	return output;
}

uint8_t* hexToByteArray(char *input)
{
	input = charArrayToUppercase(input);

    uint8_t *output;

	int len = strlen(input);
	if (len % 2 != 0)
	{
		char *temp = (char*)malloc((len + 2) * sizeof(char));
		memset(temp, 0, len + 2);

		temp[0] = '0';

		memcpy(temp + 1, input, len);
		
		free(input);
		input = (char*)malloc((len + 2) * sizeof(char));
		memset(input, 0, len + 2);
		memcpy(input, temp, len + 1);

		free(temp);
		len++;
	}

	output = (uint8_t*)malloc((len / 2) * sizeof(uint8_t));
	memset(output, 0, len / 2);

    for (int i = 0; i < len; i += 2)
  	{
    	uint8_t t = val(input[i]) << 4;
        t += val(input[i + 1]);

    	output[i / 2] = t;
  	}

	return output;
}

void hexToByteArray(const char *input, uint8_t *output)
{
	// input should be valid, a hex string: even length: % 2 = 0
	input = charArrayToUppercase(input);

	int len = strlen(input);

    for (int i = 0; i < len; i += 2)
  	{
    	uint8_t t = val(input[i]) << 4;
        t += val(input[i + 1]);

    	output[i / 2] = t;
  	}
}

string byteArrayToHexString(uint8_t *input, int len)
{
	string output = "";

	for (int i = 0; i < len; i++)
  	{
		uint8_t t = input[i] >> 4;
		output += reVal(t);

		t = input[i] & 0x0F;
		output += reVal(t);
	}

	return output;
}

char* byteArrayToHex(uint8_t *input, int len)
{
	char *output = (char*)malloc(((len * 2) + 1) * sizeof(char));
	memset(output, 0, (len * 2) + 1);

	for (int i = 0; i < len; i++)
  	{
		uint8_t t = input[i] >> 4;
		output[i * 2] = reVal(t);

		t = input[i] & 0x0F;
		output[(i * 2) + 1] = reVal(t);
	}

	return output;
}

unsigned char* byteArrayToString(uint8_t *input, int len)
{
	char *output = (char*)malloc((len + 1) * sizeof(char));
	memset(output, 0, len + 1);

	unsigned char *output2 = (unsigned char*)malloc((len + 1) * sizeof(char));
	memset(output2, 0, len + 1);

	for (int i = 0; i < len; i++)
  	{
		output[i] = (char)input[i];
		output2[i] = (unsigned char)input[i];
	}

	return output2;
}

unsigned char* secureRandomUsingOpenSSL(size_t length)
{
	unsigned char *buf;

	buf = (unsigned char*)malloc(length * sizeof(unsigned char));

	RAND_bytes(buf, length);

	return buf;
}

char* secureRandomUsingOpenSSLHex(size_t length)
{
	unsigned char *buf;

	buf = (unsigned char*)malloc(length * sizeof(unsigned char));

	RAND_bytes(buf, length);

	return byteArrayToHex(buf, length);
}

char* secureRandomUsingOpenSSLBase64(size_t length)
{
	unsigned char *buf;
	char *output;
	size_t outputLength;

	buf = (unsigned char*)malloc(length * sizeof(unsigned char));

	RAND_bytes(buf, length);

	build_decoding_table();
	output = base64_encode(buf, length, &outputLength);
	base64_cleanup();

	return output;
}

/*-------------- Below code is from: https://www.geeksforgeeks.org/convert-a-number-from-base-a-to-base-b/ ----------*/
// Original code by user: maddler
// User profile: https://www.geeksforgeeks.org/user/maddler/
/*-------------------------------------------------------------------------*/
//-------------------------- Code is modified -------------------------------------------------------
// C++ program for the above approach

// Function to return ASCII
// value of a character
int val(char c)
{
	if (c >= '0' && c <= '9')
		return (int)c - '0';
	else
		return (int)c - 'A' + 10;
}

// Function to convert a number
// from given base to decimal number
Integer convertToDecimal(string str, int base)
{
	// Stores the length
	// of the string
	int len = str.size();

	// Initialize power of base
	Integer power = 1;

	// Initialize result
	Integer num = 0;

	// Decimal equivalent is str[len-1]*1
	// + str[len-2]*base + str[len-3]*(base^2) + ...
	for (int i = len - 1; i >= 0; i--) {

		// A digit in input number must
		// be less than number's base
		if (val(toupper(str[i])) >= base) {
			printf("Invalid Number");
            cout << str[i] << endl;
            cout << val(str[i]);
			return -1;
		}

		// Update num
		num += val(toupper(str[i])) * power;

		// Update power
		power = power * base;
	}

	return num;
}

// Function to return equivalent
// character of a given value
char reVal(int num)
{
	if (num >= 0 && num <= 9)
		return (char)(num + '0');
	else
		return (char)(num - 10 + 'A');
}

// Function to convert a given
// decimal number to a given base
string convertFromDecimal(Integer input, int base)
{
	// Store the result
	string res = "";

	if (input == 0)
	{
		if (base == 10)
		{
			return "0";
		}
		else if (base > 10)
		{
			return "00";
		}
	}

	// Repeatedly divide input
	// by base and take remainder
	while (input > 0) {
		// Update res
		res += toupper(reVal(input % base));

		// Update input
		input /= base;
	}

	// Reverse the result
	reverse(res.begin(), res.end());

	if (res.size() % 2 == 1 && base > 10)
	{
		res = "0" + res;
	}

	return res;
}

// Function to convert a given number
// from a base to another base
string convertBase(string input, int fromBase, int toBase)
{
	// Convert the number from
	// base A to decimal
	Integer num = convertToDecimal(input, fromBase);

	// Convert the number from
	// decimal to base B
	string res = convertFromDecimal(num, toBase);

	return res;
}
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
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char *)malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = (unsigned char *)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void build_decoding_table() {

    decoding_table = (char *)malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}
/*-------------- [END]: Above code is from: https://www.geeksforgeeks.org/convert-a-number-from-base-a-to-base-b/ ----------*/
