obj-m += vuln_conclog.o
MODULE_NAME = vuln_conclog

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch05-concurrent-log/

.PHONY: all clean install
