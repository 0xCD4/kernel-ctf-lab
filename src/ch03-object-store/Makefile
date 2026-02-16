obj-m += vuln_objstore.o
MODULE_NAME = vuln_objstore

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch03-object-store/

.PHONY: all clean install
