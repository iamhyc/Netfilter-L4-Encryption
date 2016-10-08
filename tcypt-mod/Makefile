# AES Hook Makefile
ifneq ($(KERNELRELEASE),)
	obj-m := cryptoMod.o
	cryptoMod-objs := tcrypt.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -f .built-in.o.cmd .tcrypt*
	rm -f *.o *.cmd *.o.cmd *.ko *.mod.c *.symvers *.order
	rm -rf .tmp_versions
endif