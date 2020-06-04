#include "sm4.h"

int SM4Encrypt( unsigned char szKey[16], char *pInBuf, unsigned int inLen, unsigned char *pOutput, unsigned int *pOutLen )
{
	sm4_context ctx;
	sm4_setkey_enc(&ctx,szKey);

	int nRet = sm4_crypt_ecb(&ctx, SM4_ENCRYPT, pInBuf, inLen, pOutput, pOutLen);
	return nRet;
}

int SM4Decrypt( unsigned char szKey[16], char *pInBuf, unsigned int inLen, unsigned char *pOutput, unsigned int *pOutLen )
{
	sm4_context ctx;
	sm4_setkey_dec(&ctx, szKey);

	int nRet = sm4_crypt_ecb(&ctx, SM4_DECRYPT, pInBuf, inLen, pOutput, pOutLen);
	return nRet;
}
