obj-m += cpuinfo_spoof.o

ccflags-y += -Wno-cast-function-type
ccflags-y += -Wno-int-to-pointer-cast
ccflags-y += -Wno-declaration-after-statement

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean
