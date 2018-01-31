.PHONY: install install-lib phony

WEECHAT_HOME ?= $(HOME)/.weechat
PREFIX ?= $(WEECHAT_HOME)

lib := $(patsubst matrix/%.py, $(DESTDIR)$(PREFIX)/python/matrix/%.py, \
	 $(wildcard matrix/*.py))

install: install-lib
	install -Dm644 main.py $(DESTDIR)$(PREFIX)/python/matrix.py

install-lib: $(lib)

phony:

$(DESTDIR)$(PREFIX)/python/matrix/%.py: matrix/%.py phony
	install -Dm644 $< $@
