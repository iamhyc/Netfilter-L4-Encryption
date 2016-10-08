#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/highmem.h>

struct crypto_tfm *tfm;
#if 1
char *code = "Hello everyone,I'm Richardhesidu"
        "Hello everyone,I'm Richardhesidu"
            "Hello everyone,I'm Richardhesidu";

char *key = "00112233445566778899aabbccddeeff";
#endif

#if 0
char code[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
        0xbb,0xcc,0xdd,0xee,0xff};
char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
        0x0b,0x0c,0x0d,0x0e,0x0f};
#endif

static inline  void hexdump(unsigned char *buf,unsigned int len) {
    while(len--)
        printk("%02x",*buf++);
    printk("\n");
}

static int __init test_init(void) {
    int ret,templen,keylen,codelen;
    struct scatterlist sg[1];
    char *result;
    char *temp;

    keylen = 16;
    codelen = strlen(code)/2;
#if 0
    printk("<1>%s, codelen=%d\n",code,strlen(code));
    printk("<1>%s, keylen=%d\n",key,strlen(key));    
#endif    
    /* Allocate transform for AES ECB mode */
            
    tfm = crypto_alloc_tfm("aes",CRYPTO_TFM_MODE_ECB);
        if(IS_ERR(tfm)) {
        printk("<1>failed to load transform for aes ECB mode !\n");
                return 0;
    }

    ret = crypto_cipher_setkey(tfm,key,keylen);
    if(ret) {
        printk("<1>failed to setkey \n");
        goto failed1;
    } 
    
    sg_init_one(sg,code,codelen);
        
    /* start encrypt */
    
    ret = crypto_cipher_encrypt(tfm,sg,sg,codelen);
    if(ret) {
        printk("<1>encrypt failed \n");
        goto failed1;
    }
    
    temp = kmap(sg[0].page) + sg[0].offset;

    hexdump(temp,sg[0].length);
    
          /* start dencrypt */
    templen = strlen(temp)/2;
    sg_init_one(sg,temp,templen);
    ret = crypto_cipher_decrypt(tfm,sg,sg,templen);
        if(ret) {
                printk("<1>dencrypt failed \n");
                goto failed1;
        }

        result = kmap(sg[0].page) + sg[0].offset;
    printk("<1>%s\n",result);
//        hexdump(result,sg[0].length);


#if 0
    if(memcmp(code,result,strlen(code)) != 0)
        printk("<1>dencrpt was not successful\n");
    else
        printk("<1>dencrypt was successful\n");
#endif
failed1:
           crypto_free_tfm(tfm);
    return 0;
}

static void __exit test_exit(void)
{

}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("richardhesidu@chinaunix");