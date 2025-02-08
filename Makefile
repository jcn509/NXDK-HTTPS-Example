XBE_TITLE = NXDKHTTPSExample
GEN_XISO = $(XBE_TITLE).iso
NXDK_NET = y

# Include my files
SRCS += \
    $(CURDIR)/src/main.c

CFLAGS += \
    -I$(CURDIR)/libs/nxdk-mbedtls/include \
    -O2

include $(NXDK_DIR)/Makefile

# This is a bit hacky...
# This project should probably be built with cmake...
main.exe: libs/nxdk-mbedtls/build/library/libmbedtls.lib libs/nxdk-mbedtls/build/library/libmbedx509.lib libs/nxdk-mbedtls/build/library/libmbedcrypto.lib

clean_local:
	find . -name '*.obj' ! -path './libs/nxdk/*' -type f -delete
	find . -name '*.d' ! -path './libs/nxdk/*' -type f -delete
