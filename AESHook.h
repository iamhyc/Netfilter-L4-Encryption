#ifndef __AES_HOOK_H
#define __AES_HOOK_H

#define SRC_IP "127.0.0.1"
#define DEST_IP "127.0.0.1"

void printkHex(char *, int, int, char*);
char padding_fill(int);
char padding_check(char *, int);

#endif