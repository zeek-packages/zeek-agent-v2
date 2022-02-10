# Helper Makefile assuming build/ as the build directory, as configure does by default.

all:

.PHONY: test

test:
	$(MAKE) -C tests test
