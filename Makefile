PREFIX = /usr

all:
	@echo Run \'make install\' to install Trusted Core: RA.

install:
	@mkdir -p $(DESTDIR)$(PREFIX)/bin/
	@cp -p neofetch $(DESTDIR)$(PREFIX)/bin/neofetch
	@chmod 755 $(DESTDIR)$(PREFIX)/bin/neofetch

uninstall:
	@rm -rf $(DESTDIR)$(PREFIX)/bin/neofetch
	@rm -rf $(DESTDIR)$(MANDIR)/man1/neofetch.1*