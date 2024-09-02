#ifndef __TWOFISHWRAPPER_H__
#define __TWOFISHWRAPPER_H__

unsigned char* twofishEncrypt_256_CBC_PKCS7(const char *keyHex, const char *ivHex, unsigned char *input, uint64_t inputLength, uint64_t *outputLength);
char* twofishEncrypt_256_CBC_PKCS7_Hex(const char *keyHex, const char *ivHex, unsigned char *input, uint64_t inputLength, uint64_t *outputLength);
unsigned char* twofishDecrypt_256_CBC_PKCS7(const char *keyHex, const char *ivHex, unsigned char *input, uint64_t inputLength, uint64_t *outputLength);
unsigned char* twofishDecrypt_256_CBC_PKCS7_Hex(const char *keyHex, const char *ivHex, char *inputHex, uint64_t *outputLength);

#endif // __TWOFISHWRAPPER_H__