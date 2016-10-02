#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <memory.h>  
#include "blowfish.h"

void main()  
{  
    //TESTING Blowfish  
    //ecb test data (taken from the DES validation tests)  
    char szData[34][2][17] = {  
        {"0000000000000000", "0000000000000000"},  
        {"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF"},  
        {"3000000000000000", "1000000000000001"},  
        {"1111111111111111", "1111111111111111"},  
        {"0123456789ABCDEF", "1111111111111111"},  
        {"1111111111111111", "0123456789ABCDEF"},  
        {"0000000000000000", "0000000000000000"},  
        {"FEDCBA9876543210", "0123456789ABCDEF"},  
        {"7CA110454A1A6E57", "01A1D6D039776742"},  
        {"0131D9619DC1376E", "5CD54CA83DEF57DA"},  
        {"07A1133E4A0B2686", "0248D43806F67172"},  
        {"3849674C2602319E", "51454B582DDF440A"},  
        {"04B915BA43FEB5B6", "42FD443059577FA2"},  
        {"0113B970FD34F2CE", "059B5E0851CF143A"},  
        {"0170F175468FB5E6", "0756D8E0774761D2"},  
        {"43297FAD38E373FE", "762514B829BF486A"},  
        {"07A7137045DA2A16", "3BDD119049372802"},  
        {"04689104C2FD3B2F", "26955F6835AF609A"},  
        {"37D06BB516CB7546", "164D5E404F275232"},  
        {"1F08260D1AC2465E", "6B056E18759F5CCA"},  
        {"584023641ABA6176", "004BD6EF09176062"},  
        {"025816164629B007", "480D39006EE762F2"},  
        {"49793EBC79B3258F", "437540C8698F3CFA"},  
        {"4FB05E1515AB73A7", "072D43A077075292"},  
        {"49E95D6D4CA229BF", "02FE55778117F12A"},  
        {"018310DC409B26D6", "1D9D5C5018F728C2"},  
        {"1C587F1C13924FEF", "305532286D6F295A"},  
        {"0101010101010101", "0123456789ABCDEF"},  
        {"1F1F1F1F0E0E0E0E", "0123456789ABCDEF"},  
        {"E0FEE0FEF1FEF1FE", "0123456789ABCDEF"},  
        {"0000000000000000", "FFFFFFFFFFFFFFFF"},  
        {"FFFFFFFFFFFFFFFF", "0000000000000000"},  
        {"0123456789ABCDEF", "0000000000000000"},  
        {"FEDCBA9876543210", "FFFFFFFFFFFFFFFF"}  
    };  
    unsigned char aucKey[17];  
    unsigned char aucPlainText[64];  
    unsigned char aucCipherText[64];  
    int i;  
    for(i=0; i<34; i++)  
    {  
        Blowfish oBlowFish;  
        aucKey[16] = 0;

        memset(aucPlainText, 0x00, sizeof(aucPlainText));  
        memset(aucCipherText, 0x00, sizeof(aucCipherText));

        strcpy(aucKey, szData[i][0]);  
        strcpy(aucPlainText, szData[i][1]); 

        BlowFishInit(&oBlowFish, aucKey, 16);  

        memset(aucCipherText, 0x00, sizeof(aucCipherText));  

        Encrypt(&oBlowFish, aucPlainText, strlen(aucPlainText), aucCipherText, sizeof(aucCipherText), ECB);  

        memset(aucPlainText, 0x00, sizeof(aucPlainText)); 

        Decrypt(&oBlowFish, aucCipherText, strlen(aucCipherText), aucPlainText, sizeof(aucPlainText), ECB);  
        
        printf("[%s][%s][%s]/n", aucCipherText, aucPlainText, aucPlainText);  
  
    }  
    getchar();  
}  