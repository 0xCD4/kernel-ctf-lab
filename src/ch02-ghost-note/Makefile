obj-m += vuln_uaf.o
MODULE_NAME = vuln_uaf

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch02-ghost-note/

.PHONY: all clean install
