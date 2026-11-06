PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/cosine

.PHONY: all install uninstall test

all:
	@echo "Cosine is a pure Lua CLI. Run 'make install' to install."

install:
	@mkdir -p $(BINDIR)
	@mkdir -p $(SHAREDIR)/src
	@cp src/*.lua $(SHAREDIR)/src/
	@sed 's|$$DIR/../src|$(SHAREDIR)/src|g' bin/cosine > $(BINDIR)/cosine
	@chmod +x $(BINDIR)/cosine
	@echo "✓ Successfully installed cosine to $(BINDIR)/cosine"

uninstall:
	@rm -f $(BINDIR)/cosine
	@rm -rf $(SHAREDIR)
	@echo "✓ Successfully uninstalled cosine."

test:
	@./bin/cosine --help
