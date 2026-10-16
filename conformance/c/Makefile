# Builds the C Protocol v1 conformance runner.
#
# Prefers Homebrew's openssl@3 on macOS (the system crypto is LibreSSL and
# lacks Ed25519), then falls back to pkg-config, then to a plain -lcrypto.

CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  ifneq ($(wildcard /opt/homebrew/opt/openssl@3/.),)
    OPENSSL_CFLAGS := -I/opt/homebrew/opt/openssl@3/include
    OPENSSL_LIBS := -L/opt/homebrew/opt/openssl@3/lib \
                    -Wl,-rpath,/opt/homebrew/opt/openssl@3/lib -lcrypto
  endif
endif

ifeq ($(strip $(OPENSSL_LIBS)),)
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
  OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
endif

ifeq ($(strip $(OPENSSL_LIBS)),)
  OPENSSL_LIBS := -lcrypto
endif

permit-conformance: permit-conformance.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ permit-conformance.c $(OPENSSL_LIBS)

clean:
	rm -f permit-conformance

.PHONY: clean
