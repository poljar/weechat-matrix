.PHONY: install install-lib install-dir uninstall phony test typecheck

WEECHAT_HOME ?= $(HOME)/.weechat
PREFIX ?= $(WEECHAT_HOME)
PYTHON ?= python

lib := $(patsubst matrix/%.py, $(DESTDIR)$(PREFIX)/python/matrix/%.py, \
	 $(wildcard matrix/*.py))

install: install-dir install-lib
	install -m644 main.py $(DESTDIR)$(PREFIX)/python/matrix.py

install-lib: $(lib)
install-dir:
	install -d $(DESTDIR)$(PREFIX)/python/matrix

uninstall:
	rm $(DESTDIR)$(PREFIX)/python/matrix.py $(DESTDIR)$(PREFIX)/python/matrix/*
	rmdir $(DESTDIR)$(PREFIX)/python/matrix

phony:

$(DESTDIR)$(PREFIX)/python/matrix/%.py: matrix/%.py phony
	install -m644 $< $@

test:
	python3 -m pytest
	python2 -m pytest

typecheck:
	mypy -p matrix --ignore-missing-imports --warn-redundant-casts
