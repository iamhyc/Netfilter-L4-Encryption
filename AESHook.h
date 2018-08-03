#ifndef __AES_HOOK_H
#define __AES_HOOK_H

#define LOCAL_IP "127.0.0.1" //FIXME:get over iface
#define REMOTE_IP "127.0.0.1" //FIXME:rewrite to list (with addr mask)

void printkHex(char *, int, int, char*);
char padding_fill(int);
char padding_check(char *, int);

char padding_fill(int data_len) {
	char tmp_len = 0;

	tmp_len = data_len % 16;
	tmp_len = (tmp_len==0?0:16-tmp_len);

	return tmp_len;
}

char padding_check(char * data, int len)
{
	char ex;
	int flag = 0, i = 0;

	ex = data[len - 1];
	if (ex < 1 || ex > 15)
		return 0;

	for (i = 1; i < ex; i++)
	{
		flag += data[len - i - 1];
	}

	if(flag==0)
		return ex;
	else
		return 0;
}

unsigned int nf_hookfn_in(void *, struct sk_buff *, const struct nf_hook_state *);
unsigned int nf_hookfn_out(void *, struct sk_buff *, const struct nf_hook_state *);

#endif