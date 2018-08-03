
MOD=AESHookMod

ifneq ($(KERNELRELEASE),)
	obj-m := $(MOD).o
	$(MOD)-objs := AESHook.o aes_method.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:build-krn build-usr

build-krn:
	$(MAKE) -C $(KDIR) M=$(PWD)

build-usr:
	@echo "ERROR: No Userspace Program Found."

install:
	cp -f $(MOD).ko /lib/modules/$(shell uname -r)

clean:
	rm -f .cache.mk .*.cmd
	rm -f *.o *.o.cmd *.ko *.mod.c *.symvers *.order
	rm -rf .tmp_versions
endif