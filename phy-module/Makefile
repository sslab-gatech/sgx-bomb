obj-m = phyaddr.o

M=$(shell pwd)

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(M) modules

clean:
	rm -rf *.ko *.mod.* *.o *.cmd *.order .*.cmd *.symvers .tmp_versions *.o.ur-safe

