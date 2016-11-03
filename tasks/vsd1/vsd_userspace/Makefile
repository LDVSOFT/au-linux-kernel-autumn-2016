INCLUDE_PATH=../vsd_driver/
include ../config.mk

vsd_userspace: main.c $(INCLUDE_PATH)/vsd_ioctl.h
	gcc $< -I$(INCLUDE_PATH) -o $@
	cp $@ $(VM_SHARE_PATH)

.PHONY: clean

clean:
	rm -rf vsd_userspace
