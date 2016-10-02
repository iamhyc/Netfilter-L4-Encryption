#ifndef __BLOWFISH_H__  
#define __BLOWFISH_H__  
#define ECB 0 /*default*/  
#define CBC 1  
#define CFB 2  
#define MAX_KEY_SIZE 56  
#define MAX_PBLOCK_SIZE 18  
#define MAX_SBLOCK_XSIZE 4  
#define MAX_SBLOCK_YSIZE 256  
/*Block Structure*/  
typedef struct{  
    unsigned int m_uil; /*Hi*/  
    unsigned int m_uir; /*Lo*/  
}SBlock;  
typedef struct{  
    SBlock m_oChain;  
    unsigned int m_auiP[MAX_PBLOCK_SIZE];  
    unsigned int m_auiS[MAX_SBLOCK_XSIZE][MAX_SBLOCK_YSIZE];  
}Blowfish;  
/****************************************************************************************/  
/*Constructor - Initialize the P and S boxes for a given Key*/  
int BlowFishInit(Blowfish *blowfish, unsigned char* ucKey, size_t keysize);  
/*Encrypt/Decrypt from Input Buffer to Output Buffer*/  
int Encrypt(Blowfish *blowfish, const unsigned char* in, size_t siz_i, unsigned char* out, size_t siz_o, int iMode);  
int Decrypt(Blowfish *blowfish, const unsigned char* in, size_t siz_i, unsigned char* out, size_t siz_o, int iMode);  
/****************************************************************************************/  
void HexStr2CharStr(unsigned char *pszHexStr, int iSize, unsigned char *pucCharStr);  
void CharStr2HexStr(unsigned char *pucCharStr, int iSize,unsigned char *pszHexStr);  
#endif /*__BLOWFISH_H__*/  