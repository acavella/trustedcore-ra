PREFIX = /usr

all:
	@echo Run \'make install\' to install Trusted Core: RA.

install:
	@mkdir -p $(HOME)/tcra
	@cp -r source/* $(HOME)/tcra
	@chmod 755 genreq
	@chmod 755 signcert
	@chmod 755 genp12

uninstall:
	@rm -rf $(HOME)/tcra