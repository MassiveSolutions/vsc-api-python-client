.PHONY: all clean doc install

all:

clean:
	find . -name '*.py[co]' -delete
	rm -rf -- build *.egg-info
	$(MAKE) -C doc $@

doc:
	$(MAKE) -C doc

install:
	python setup.py install --root=$(DESTDIR) --prefix=/usr --install-layout=deb
