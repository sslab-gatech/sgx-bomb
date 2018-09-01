MODULE_DIR ?= $(base_dir)/phy-module
ENCLAVE_DIR ?= $(base_dir)/enclave-hammer

base_dir = $(abspath .)
num_proc = $(shell nproc)

all: $(MODULE_DIR)/phyaddr.ko $(ENCLAVE_DIR)/app

install: $(MODULE_DIR)/phyaddr.ko
	sudo insmod $(MODULE_DIR)/phyaddr.ko

run: $(ENCLAVE_DIR)/app
	cd $(ENCLAVE_DIR) && ./app $(num_proc)

clean: 
	cd $(MODULE_DIR) && make clean
	cd $(ENCLAVE_DIR) && make clean
	sudo rmmod phyaddr


$(MODULE_DIR)/phyaddr.ko:
	cd $(MODULE_DIR) && make


$(ENCLAVE_DIR)/app: 
	cd $(ENCLAVE_DIR) && make SGX_DEBUG=0 SGX_PRERELEASE=1

