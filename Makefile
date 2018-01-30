.PHONY: install install-lib

WEECHAT_HOME ?= $(HOME)/.weechat
PREFIX ?= $(WEECHAT_HOME)

lib := $(patsubst matrix/%.py, $(DESTDIR)$(PREFIX)/python/matrix/%.py, \
	 $(wildcard matrix/*.py))

install: install-lib
	install -Dm644 main.py $(DESTDIR)$(PREFIX)/python/matrix.py

install-lib: $(lib)

$(DESTDIR)$(PREFIX)/python/matrix/%.py: matrix/%.py
	install -Dm644 $< $@
