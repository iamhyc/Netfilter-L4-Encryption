
MOD=nl4_bypass

ifneq ($(KERNELRELEASE),)
	obj-m := $(MOD).o
	$(MOD)-objs := nl4_entry.o nl4_utility.o
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

insmod:
	sudo insmod $(MOD).ko

rmmod:
	sudo rmmod $(MOD)

clean:
	rm -f .cache.mk .*.cmd
	rm -f *.o *.o.cmd *.ko *.mod.c *.symvers *.order
	rm -rf .tmp_versions
endif