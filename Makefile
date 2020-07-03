.PHONY: install install-lib install-dir uninstall phony test typecheck

WEECHAT_HOME ?= $(HOME)/.weechat
PREFIX ?= $(WEECHAT_HOME)
PYTHON ?= python

INSTALLDIR := $(DESTDIR)$(PREFIX)/python/matrix

lib := $(patsubst matrix/%.py, $(INSTALLDIR)/%.py, \
	 $(wildcard matrix/*.py))

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install: install-lib | $(INSTALLDIR) ## Install the plugin to $(DESTDIR)/$(PREFIX)
	install -m644 main.py $(DESTDIR)$(PREFIX)/python/matrix.py

install-lib: $(lib)
$(INSTALLDIR):
	install -d $@

uninstall: ## Uninstall the plugin from $(PREFIX)
	rm $(DESTDIR)$(PREFIX)/python/matrix.py $(INSTALLDIR)/*
	rmdir $(INSTALLDIR)

phony:

$(INSTALLDIR)/%.py: matrix/%.py phony | $(INSTALLDIR)
	install -m644 $< $@

test: ## Run automated tests
	python3 -m pytest
	python2 -m pytest

typecheck: ## Run type check
	mypy -p matrix --ignore-missing-imports --warn-redundant-casts
