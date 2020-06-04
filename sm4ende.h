#ifndef _SM4_ENDE_H
#define _SM4_ENDE_H



int SM4Encrypt( unsigned char szKey[16], char *pInBuf, unsigned int inLen, unsigned char *pOutput, unsigned int *pOutLen );
int SM4Decrypt( unsigned char szKey[16], char *pInBuf, unsigned int inLen, unsigned char *pOutput, unsigned int *pOutLen );




#endif
