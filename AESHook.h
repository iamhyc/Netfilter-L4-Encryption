#ifndef __AES_HOOK_H
#define __AES_HOOK_H

#define srcIP "127.0.0.0"
#define destIP "127.0.0.0"

void printkHex(char *, int, int, char*);
char padding_fill(int);
char padding_check(char *, int);

#endif