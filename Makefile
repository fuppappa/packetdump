DROID_KERNEL_DIR=/home/fuppaubuntu/mydroid/kernel/msm
#ubuntu or cent only
obj-m += packetmod.o
PWD := $(shell pwd)
VERBOSE = 0
packetmod-objs := packetlog.o
ANDROID_CSET = ARCH=arm CROSS_COMPILE=arm-eabi-

ifeq ($(DEST), cent)
 KERNEL_DIR=/lib/modules/$(shell uname -r)/build
else
 KERNEL_DIR=/usr/src/linux-headers-$(shell uname -r)
endif 

all: 
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) KBUILD_VERBOSE=$(VERBOSE) modules

.PHONY: android 
android:
	$(MAKE) $(ANDROID_CSET) -C $(DROID_KERNEL_DIR) M=$(PWD) KBUILD_VERBOSE=$(VERBOSE) modules

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) KBUILD_VERBOSE=$(VERBOSE) modules


clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
