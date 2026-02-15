obj-m += vuln_race.o
MODULE_NAME = vuln_race

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp $(MODULE_NAME).ko ../../challenges/ch03-timewarp/

.PHONY: all clean install
