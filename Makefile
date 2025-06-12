obj-m := extended-minidetect.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo cp extended-minidetect.ko /lib/modules/$(shell uname -r)/kernel/drivers/misc/
	sudo depmod -a
	sudo modprobe extended_minidetect

uninstall:
	sudo rmmod extended_minidetect
	sudo rm -f /lib/modules/$(shell uname -r)/kernel/drivers/misc/extended-minidetect.ko
	sudo depmod -a

.PHONY: all clean install **uninstall**
