GoLismero-fingerprinter
=======================

GoLismero fingerprinter is a tool that aims to compile as many signatures of web servers as possible and make a large database.

The database is based on methods, formats and original database of [httprecon project](http://www.computec.ch/projekte/httprecon/). Results will published as part of GoLismero 2.0 project (currently in active develop). 

This method is an advanced way to detect remote web server by analyzing HTTP headers (not only the remote server banner).

The actual database is available in current branch of GoLismero:

[https://github.com/cr0hn/golismero/tree/2.0.0/wordlist/fingerprint/httprecon](https://github.com/cr0hn/golismero/tree/2.0.0/wordlist/fingerprint/httprecon)

How to download?
================

For clone this branch you must write:

git clone -b fingerprinter https://github.com/cr0hn/golismero.git golismero-fingerprinter


How to run fingerprinter
=======================

You can run the fingerprinter over your webserver like this:

python golismero-fingerprinter.py 10.0.0.1 10.5.5.1/24 myserver.com 192.168.1.22:8080


How to collaborate?
===================

After execute golismero-fingerprinter.py it will create a ".tar.gz" file. You can collaborate with de golismero-fingerprinter project sending us the file result to:

golismero.project #- AT -# gmail _dot_ com
