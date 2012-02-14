all:

distclean:
	rm -rf ./build ./dist ./*.egg-info
	rm -f auth_mac/*.pyc
	rm -f auth_mac/test/*.pyc

dist:
	python setup.py sdist