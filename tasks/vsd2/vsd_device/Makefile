MOD_NAME := vsd

ifneq ($(KERNELRELEASE),)
	obj-m := $(MOD_NAME).o
	$(MOD_NAME)-objs := module.o
else
	include ../sub_config.mk
all:
	$(MAKE) -C $(KDIR) M=$$PWD
	cp $(MOD_NAME).ko $(VM_SHARE_PATH)

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
endif
