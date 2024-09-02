#include <iostream>
#include <sstream>
#include <stdio.h>
#include "../../include/Utils/Common.h"
#include "../../include/Cryptography/Twofish.h"
#include "../../include/Cryptography/TwofishWrapper.h"

unsigned char* twofishEncrypt_256_CBC_PKCS7(const char *keyHex, const char *ivHex, unsigned char *input, uint64_t inputLength, uint64_t *outputLength)
{
    Twofish_context context;
    uint8_t *key;
    Twofish_Byte iv[16];
    uint64_t length = 0;
    //uint64_t outputLength = 0;
    uint8_t *output;
    uint8_t *outputTemp;

    length = inputLength;
    *outputLength = length;

    key = hexToByteArray(keyHex);
    hexToByteArray(ivHex, iv);

    Twofish_initialise();

    Twofish_prepare_key(key, 32, &(context.key));
    memcpy(context.iv, iv, 16);
    context.options = (Twofish_options)(Twofish_options::Twofish_option_CBC | 
        Twofish_options::Twofish_option_PaddingPKCS7);

    *outputLength = Twofish_get_output_length(&context, length);
    outputTemp = (uint8_t*)malloc(*outputLength * sizeof(uint8_t));
    memset(outputTemp, 0, *outputLength);

    Twofish_encrypt(&context, input, length, outputTemp, *outputLength);

    output = (uint8_t*)malloc(*outputLength * sizeof(uint8_t));
    memcpy(output, outputTemp, *outputLength);

    free(key);
    free(outputTemp);
    return output;
}

char* twofishEncrypt_256_CBC_PKCS7_Hex(const char *keyHex, const char *ivHex, unsigned char *input, uint64_t inputLength, uint64_t *outputLength)
{
    Twofish_context context;
    uint8_t *key;
    Twofish_Byte iv[16];
    uint64_t length = 0;
    //uint64_t outputLength = 0;
    uint8_t *output;
    char *outputHex;

    length = inputLength;
    *outputLength = length;

    key = hexToByteArray(keyHex);
    hexToByteArray(ivHex, iv);

    Twofish_initialise();

    Twofish_prepare_key(key, 32, &(context.key));
    memcpy(context.iv, iv, 16);
    context.options = (Twofish_options)(Twofish_options::Twofish_option_CBC | 
        Twofish_options::Twofish_option_PaddingPKCS7);

    *outputLength = Twofish_get_output_length(&context, length);
    output = (uint8_t*)malloc(*outputLength * sizeof(uint8_t));
    memset(output, 0, *outputLength);

    Twofish_encrypt(&context, input, length, output, *outputLength);

    outputHex = byteArrayToHex(output, *outputLength);

    free(key);
    free(output);
    return outputHex;
}

unsigned char* twofishDecrypt_256_CBC_PKCS7(const char *keyHex, const char *ivHex, unsigned char *input, uint64_t inputLength, uint64_t *outputLength)
{
    Twofish_context context;
    uint8_t *key;
    Twofish_Byte iv[16];
    uint64_t length = 0;
    uint64_t outputLengthTemp = 0;
    uint8_t *output;
    uint8_t *outputTemp;

    length = inputLength;
    *outputLength = length;
    outputLengthTemp = length;

    key = hexToByteArray(keyHex);
    hexToByteArray(ivHex, iv);

    Twofish_initialise();

    Twofish_prepare_key(key, 32, &(context.key));
    memcpy(context.iv, iv, 16);
    context.options = (Twofish_options)(Twofish_options::Twofish_option_CBC | 
        Twofish_options::Twofish_option_PaddingPKCS7);

    outputTemp = (uint8_t*)malloc(*outputLength * sizeof(uint8_t));
    memset(outputTemp, 0, *outputLength);
    
    Twofish_decrypt(&context, input, length, outputTemp, &outputLengthTemp);

    *outputLength = outputLengthTemp;
    output = (uint8_t*)malloc(*outputLength * sizeof(uint8_t));
    memcpy(output, outputTemp, *outputLength);

    free(key);
    free(outputTemp);
    return output;
}

unsigned char* twofishDecrypt_256_CBC_PKCS7_Hex(const char *keyHex, const char *ivHex, char *inputHex, uint64_t *outputLength)
{
    Twofish_context context;
    uint8_t *key;
    Twofish_Byte iv[16];
    uint64_t length = 0;
    uint8_t *inputUInt8;
    uint64_t outputLengthTemp = 0;
    uint8_t *output;
    uint8_t *outputTemp;

    inputUInt8 = hexToByteArray(inputHex);

    length = (uint64_t)(strlen(inputHex) / 2);
    *outputLength = length;
    outputLengthTemp = length;
    
    key = hexToByteArray(keyHex);
    hexToByteArray(ivHex, iv);

    Twofish_initialise();

    Twofish_prepare_key(key, 32, &(context.key));
    memcpy(context.iv, iv, 16);
    context.options = (Twofish_options)(Twofish_options::Twofish_option_CBC | 
        Twofish_options::Twofish_option_PaddingPKCS7);

    outputTemp = (uint8_t*)malloc(*outputLength * sizeof(uint8_t));
    memset(outputTemp, 0, *outputLength);
    
    Twofish_decrypt(&context, inputUInt8, length, outputTemp, &outputLengthTemp);
    
    *outputLength = outputLengthTemp;
    output = (uint8_t*)malloc(outputLengthTemp * sizeof(uint8_t));
    memcpy(output, outputTemp, outputLengthTemp);

    free(key);
    free(inputUInt8);
    free(outputTemp);
    return output;
}

