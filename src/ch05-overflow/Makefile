obj-m += vuln_intovf.o
MODULE_NAME = vuln_intovf

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch05-overflow/

.PHONY: all clean install
