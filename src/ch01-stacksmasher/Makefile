obj-m += vuln_stack.o
MODULE_NAME = vuln_stack

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch01-stacksmasher/

.PHONY: all clean install
