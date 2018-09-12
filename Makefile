.PHONY: install install-lib phony test typecheck

WEECHAT_HOME ?= $(HOME)/.weechat
PREFIX ?= $(WEECHAT_HOME)
PYTHON ?= python

lib := $(patsubst matrix/%.py, $(DESTDIR)$(PREFIX)/python/matrix/%.py, \
	 $(wildcard matrix/*.py))

install: install-lib
	install -Dm644 main.py $(DESTDIR)$(PREFIX)/python/matrix.py

install-lib: $(lib)

phony:

$(DESTDIR)$(PREFIX)/python/matrix/%.py: matrix/%.py phony
	install -Dm644 $< $@

test:
	python3 -m pytest
	python2 -m pytest

typecheck:
	mypy -p matrix --ignore-missing-imports --warn-redundant-casts
