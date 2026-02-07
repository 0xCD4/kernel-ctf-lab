obj-m += vuln_secalloc.o
MODULE_NAME = vuln_secalloc

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch04-secure-alloc/

.PHONY: all clean install
