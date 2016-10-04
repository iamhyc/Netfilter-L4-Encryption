# AES Hook Makefile
ifneq ($(KERNELRELEASE),)
	AESHook-Mod-obj := AESHook.o
	obj-m := AESHook-Mod.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -rf *.o .cmd *.ko *.mod.c .tmp_versions
endif