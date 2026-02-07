obj-m += vuln_echo.o
MODULE_NAME = vuln_echo

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch01-echo-chamber/

.PHONY: all clean install
