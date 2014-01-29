.PHONY: all clean

PKG = VscApiClient

FIGURES = $(patsubst %.dot, %.png, $(wildcard *.dot))
PAGES = $(patsubst ../$(PKG)/%.py, $(PKG).%.html, \
    $(filter-out ../$(PKG)/__init__.py, \
    $(wildcard ../$(PKG)/*.py))) $(PKG).html

export PYTHONPATH := ..:$(PYTHONPATH)

all: $(FIGURES) $(PAGES)

%.png: %.dot
	dot -T png $< > $@

$(PKG).%.html: ../$(PKG)/%.py
	pydoc -w $(patsubst $(PKG).%.html, $(PKG).%, $@)

$(PKG).html: ../$(PKG)/__init__.py
	pydoc -w $(PKG)

clean:
	rm --force -- $(FIGURES) $(PAGES) *~
