GoLismero-fingerprinter
=======================

GoLismero fingerprinter is a tool that aims to compile as many signatures of web servers as possible and make a large database.

The database is based on methods, formats and original contents from the [httprecon project](http://www.computec.ch/projekte/httprecon/). Results will published as part of GoLismero 2.0 project (currently in active development). 

This method is an advanced way to detect remote web servers by analyzing HTTP headers (not only the "Server" banner).

The most up to date database is available at:

[https://github.com/cr0hn/golismero/tree/2.0.0/wordlist/fingerprint/httprecon](https://github.com/cr0hn/golismero/tree/2.0.0/wordlist/fingerprint/httprecon)

How to download?
================

To clone this branch enter the following command:

git clone -b fingerprinter https://github.com/cr0hn/golismero.git golismero-fingerprinter


How to run?
===========

You can run the fingerprinter over your webserver like this:

python golismero-fingerprinter.py 10.0.0.1 10.5.5.1/24 myserver.com 192.168.1.22:8080


How to collaborate?
===================

After executing golismero-fingerprinter.py you will find a ".tar.gz" file. You can collaborate with the golismero-fingerprinter project by sending us the file to:

golismero.project #- AT -# gmail _dot_ com
