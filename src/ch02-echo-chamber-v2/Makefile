obj-m += vuln_echo2.o
MODULE_NAME = vuln_echo2

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch02-echo-chamber-v2/

.PHONY: all clean install
