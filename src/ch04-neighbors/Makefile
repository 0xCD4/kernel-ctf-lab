obj-m += vuln_heap.o
MODULE_NAME = vuln_heap

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch04-neighbors/

.PHONY: all clean install
