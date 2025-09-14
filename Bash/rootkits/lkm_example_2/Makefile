obj-m += educational_rootkit.o

# Get the kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Default target
all:
	make -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	make -C $(KDIR) M=$(PWD) clean

# Install target (requires root)
install:
	make -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# Help target
help:
	@echo "Available targets:"
	@echo "  all     - Build the kernel module"
	@echo "  clean   - Clean build artifacts"
	@echo "  install - Install the module (requires root)"
	@echo ""
	@echo "To load the module after building:"
	@echo "  sudo insmod educational_rootkit.ko"
	@echo ""
	@echo "To unload the module:"
	@echo "  sudo rmmod educational_rootkit"
	@echo ""
	@echo "To check the forensic log:"
	@echo "  cat /proc/rootkit_forensics"