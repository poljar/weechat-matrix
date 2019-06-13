.PHONY: install install-lib install-dir uninstall phony test typecheck

WEECHAT_HOME ?= $(HOME)/.weechat
PREFIX ?= $(WEECHAT_HOME)
PYTHON ?= python

lib := $(patsubst matrix/%.py, $(DESTDIR)$(PREFIX)/python/matrix/%.py, \
	 $(wildcard matrix/*.py))

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install: install-dir install-lib ## Install the plugin to $(DESTDIR)/$(PREFIX)
	install -m644 main.py $(DESTDIR)$(PREFIX)/python/matrix.py

install-lib: $(lib)
install-dir:
	install -d $(DESTDIR)$(PREFIX)/python/matrix

uninstall: ## Uninstall the plugin from $(PREFIX)
	rm $(DESTDIR)$(PREFIX)/python/matrix.py $(DESTDIR)$(PREFIX)/python/matrix/*
	rmdir $(DESTDIR)$(PREFIX)/python/matrix

phony:

$(DESTDIR)$(PREFIX)/python/matrix/%.py: matrix/%.py phony
	install -m644 $< $@

test: ## Run automated tests
	python3 -m pytest
	python2 -m pytest

typecheck: ## Run type check
	mypy -p matrix --ignore-missing-imports --warn-redundant-casts
