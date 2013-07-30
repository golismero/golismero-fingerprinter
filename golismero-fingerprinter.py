#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
GoLismero fingerprinter - Copyright (C) 2011-2013

This file is part of GoLismero project.

Authors:
  Daniel Garcia Garcia a.k.a cr0hn | cr0hn@cr0hn.com
  Mario Vilas | mvilas@gmail.com

Golismero project site: http://code.google.com/p/golismero/
Golismero project mail: golismero.project@gmail.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""





#----------------------------------------------------------------------
# Python version check.
# We must do it now before trying to import any more modules.
#
# Note: this is mostly because of argparse, if you install it
#       separately you can try removing this check and seeing
#       what happens (we haven't tested it!).


from sys import version_info, exit

if __name__ == "__main__":
	if version_info < (2, 7) or version_info >= (3, 0):
		show_banner()
		print "[!] You must use Python version 2.7"
		exit(1)


import socket
import argparse
import os.path
import sys
from urlparse import urljoin
from mimetools import Message
from StringIO import StringIO
from select import select
from urlparse import urlparse
import tarfile

_NETADDR_ = False
try:
	from netaddr import *
	_NETADDR_ = True
except ImportError:
	pass

# Show program banner
def show_banner():
	print
	print "|--------------------------------------------------|"
	print "| GoLismero project: GoLismero fingerprinter       |"
	print "| Contact: golismero.project<@>gmail.com           |"
	print "|                                                  |"
	print "| Daniel Garcia a.k.a cr0hn (@ggdaniel)            |"
	print "| Mario Vilas (@mario_vilas)                       |"
	print "|--------------------------------------------------|"
	print


#----------------------------------------------------------------------
def get_HTTP(host, request_content, timeout = 2, port=80):
	"""
	This method allow you to make raw connections to a host.

	You need to provide the data that you want to send to the server. You're the responsible to manage the
	data that will be send to the server.

	:param timeout: timeout in seconds.
	:type timeout: int

	:return: dict as format: {'protocol' : "HTTP", "version": "x.x", "statuscode": "XXX", "statustext": "XXXXX", 'headers': Message()}

	"""

	# Start timing the request
	try:
		# Connect to the server
		s = socket.socket()
		try:
			s.settimeout(timeout)
			s.connect((host, int(port)))
			try:

				# Send an HTTP request
				s.send(request_content)

				m_response    = StringIO()

				# Wait for response
				m_read, m_write, m_error = select([s], [], [], timeout)

				if not m_read:
					#s.close()
					raise socket.error("Socket timeout")

				buffer        = s.recv(1)
				m_response.write( buffer )

				# When server close the remote connection send, in ASCII, the
				# character "<"
				if buffer == "<":
					raise socket.error("Connection closed for remote server")

				m_counter     = 0
				if buffer == '\n' or buffer == '\r':
					m_counter += 1


				while True:
					buffer = s.recv(1)
					m_response.write( buffer )
					m_counter = m_counter + 1 if buffer == '\n' or buffer == '\r' else 0
					if m_counter == 4: # End of HTTP header
						break

			# Clean up the socket
			finally:
				try:
					s.shutdown(2)
				except socket.error:
					pass

		finally:
			try:
				s.close()
			except socket.error:
				pass

		request_line, headers_alone = m_response.getvalue().split('\n', 1)

		m_response = {}

		# Parse first line
		m_response["protocol"]    = request_line[0:4]
		m_response["version"]     = request_line[5:8]
		m_response["statuscode"]  = request_line[9:12]
		m_response["statustext"]  = request_line[13:]

		# Build headers
		m_response["headers"]     = Message(StringIO(headers_alone))

		return m_response

	except socket.error, e:
		raise socket.error(e)






#----------------------------------------------------------------------
def cmdline_parser():
	""""""

	m_examples = '''Examples:
	%(prog)s -d .dicts 1.1.1.1
	%(prog)s 1.1.1.1:8080
	%(prog)s -d exit_wordlists 1.1.1.1 1.1.1.1:8080 2.2.2.2/24 9.1.1.1/16

	Test an specific URI:
	%(prog)s -d exit_wordlists -u /my/custom/uri/index.html my_site.com:8080

	Test ports '80,8080,9000-10000' in all hotst:
	%(prog)s -p 80,8080,9000-10000 -d exit_wordlists 1.1.1.1 2.2.2.2/24

	Load some hosts from file:
	%(prog)s -d exit_wordlists 1.1.1.1:8080 hosts.txt

	Test ports '80,8080' in all hotst and their own:
	%(prog)s -p 80,8080 -d exit_wordlists 1.1.1.1:8000,8001,9000-9005 2.2.2.2/24
	''' % { "prog" : " golismero-fingerprinter.py"}

	#----------------------------------------------------------------------
	# Command line parser using argparse
	m_parser = argparse.ArgumentParser(fromfile_prefix_chars="@",formatter_class=argparse.RawDescriptionHelpFormatter,  epilog=m_examples)
	m_parser.add_argument("targets", metavar="TARGET", nargs="+", help="one or more hosts")
	m_parser.add_argument("-d", metavar="DST_DIR", dest="dst_dir", help="Destination dir with the results (Default dicts/)", default="./dicts/")
	m_parser.add_argument("-v", action="store_true", dest="verbose", help="verbose mode", default=False)
	m_parser.add_argument("--no-create-dir", action="store_false", dest="auto_create_dir", help="not create automatically the results dir", default=True)
	m_parser.add_argument("--no-package", action="store_false", dest="no_package", help="not create the .tar.gz file.", default=True)
	m_parser.add_argument("--splited-results", action="store_true", dest="splited_results", help="split file results. One file for each IP.", default=False)
	m_parser.add_argument("-p", metavar="PORTS", dest="ports", help="specify global ports to test in all hosts", default=None)
	m_parser.add_argument("-u", metavar="URI", dest="base_uri", help="specify base URI for al hosts.", default=None)
	return m_parser

#----------------------------------------------------------------------
def split_ports(ports):
	""""""
	m_return         = []
	m_return_append  = m_return.append
	m_return_extend  = m_return.extend
	for l_p in ports.split(","):
		if l_p.find("-") != -1:
			l_pp = l_p.split("-")
			if len (l_pp) != 2:
				raise ValueError("Host '%s' has not valid format. Exiting..." % l_h)

			m_return_extend(range(int(l_pp[0]), int(l_pp[1])))

		elif l_p.isdigit():
			m_return_append(l_p)
		else:
			raise ValueError("Host '%s' has not valid format. Exiting..." % l_h)

	return m_return

#----------------------------------------------------------------------
def main(args):
	""""""
	show_banner()

	parser = cmdline_parser()

	try:
		P      = parser.parse_args(args)
	except Exception,e:
		print parser.error(str(e))

	# Filter dir
	m_dst_dir = os.path.abspath(P.dst_dir)
	if not os.path.exists(m_dst_dir):
		if not P.auto_create_dir:
			print "[!] Directory '%s' not exits. Exiting..." % P.dst_dir
			exit(1)
		else:
			os.makedirs(m_dst_dir)


	m_cmd_hosts         = set()
	m_cmd_hosts_update  = m_cmd_hosts.update
	m_cmd_hosts_add     = m_cmd_hosts.add

	# Read the user targets
	for t in P.targets:

		# Targets in file?
		l_input_file = os.path.abspath(t)
		if os.path.exists(l_input_file):
			# Read targets
			m_cmd_hosts_update([ h.replace("\n","").replace("\r", "") for h in open(l_input_file, "rU").readlines()])
			continue

		# Targets from comman line
		m_cmd_hosts_add(t)


	# Extract the hosts
	l_targets          = []
	l_targets_append   = l_targets.append
	l_targets_extend   = l_targets.extend

	for l_h in m_cmd_hosts:

		if l_h.find("/") != -1:
			if not _NETADDR_:
				print "[!] netadd librarie are not available. You can't use mask format (IP/MASK) "
				exit(1)
			l_targets_extend([str(t) for t in IPNetwork(l_h)])
		# For cases like -> 1.1.1.1:80-8080
		elif l_h.find("-") != -1:
			if not l_h.find(":") == -1:
				if not _NETADDR_:
					print "[!] netadd librarie are not available. You can't use mask format (IP1-IP2) "
					exit(1)

				l_sp = l_h.split("-")
				l_targets_extend([str(t) for t in IPRange(l_sp[0], l_sp[1])])
		else:
			l_targets_append(l_h)



	# Format the hosts
	m_parsed_ips        = []
	m_parsed_ips_extend = m_parsed_ips.extend
	for l_h in l_targets:

		# Check if IP is IPv6
		m_ip_v6 = False
		try:
			b = IPAddress(l_h)
			if b.version == 6:
				m_ip_v6 = True
		except Exception:
			pass

		# Check for ranges
		l_host = None

		# For IPv6
		if not m_ip_v6:
			# Check for ports
			l_sp   = l_h.split(":")
			l_host = l_sp[0]
			l_port = None

			# If not global ports
			if len(l_sp) == 1:
				l_port = [80]
			elif len(l_sp) == 2:
				try:
					l_port = split_ports(l_sp[1])
				except ValueError,e:
					print "[!] %s" % e.message
					exit(1)

			else:
				print "[!] Host '%s' has not valid format. Exiting..." % l_h
				exit(1)

			# Store
			m_parsed_ips_extend([(l_host, x) for x in l_port])

		# Append global ports
		if P.ports:
			try:
				l_port = split_ports(P.ports)
			except ValueError,e:
				print "[!] %s" % e.message
				exit(1)

			m_parsed_ips_extend([(l_host, x) for x in l_port])

	# Run analyzer
	print "[*] Starting headers analysis"
	m_files        = []
	m_files_append = m_files.append



	if P.splited_results:

		for l_ip in m_parsed_ips:

			# Create dir for each IP
			l_ip_only  = l_ip[0]
			l_dst      = os.path.abspath(os.path.join(m_dst_dir, l_ip_only))
			if not os.path.exists(l_dst):
				os.makedirs(l_dst)

			m_error = http_analyzer_only_one_ip(l_ip, l_dst, P.base_uri, P.verbose)

			if not m_error:
				# Add to files to compress
				m_files_append(l_dst)
			else:
				print "A lot of error found for '%s'. Can't generate wordlists." % l_ip

	else:
		print m_dst_dir
		m_error = http_analyzers(m_parsed_ips, m_dst_dir, P.base_uri, P.verbose)

		if not m_error:
			m_files_append(m_dst_dir)
		else:
			print "A lot of error found for '%s'. Can't generate wordlists." % ''.join(m_parsed_ips)

	#
	# Compress the results
	#
	if P.no_package:
		print "\n    Results:"
		for l_f in m_files:
			l_file = "%s.tar.gz" % l_f
			z = tarfile.open(l_file, "w:gz")
			z.add(m_dst_dir, arcname="wordlists")
			z.close()

			print "    -> '%s'" % l_file

		print ""
		print "    PLEASE, SEND THIS FILE FOR CONTRIBUTE WITH THE PROJECT: golismero.project@gmail.com"
		print ""

	print "[*] Done\n"

#----------------------------------------------------------------------
def http_analyzer_only_one_ip(IP, dst_dir, uri, verb):
	return http_analyzers([IP], dst_dir, uri, verb)

#----------------------------------------------------------------------
def http_analyzers(IPs, dst_dir, uri, verb):
	"""
	Analyze HTTP headers for detect the web server. Return a list with most possible web servers.

	:param IPs: List of IPs with services as format: (('IP1','port1'), ('IP2','port2'), ...)
	:type IPs: dict()

	:param dst_dir: Destination dir to store the results.
	:type dst_dir: str

	:return: True if all it's ok. False otherwise.
	:rtype: bool

	"""

	m_errors                = 0

	# Parse URI
	m_uri = None
	if not uri:
		m_uri = ""
	else:
		p     = urlparse(uri).path
		pf    = p.rfind("/")
		if pf != -1:
			m_uri = p[:pf]
		else:
			m_uri = ""

	# Load wordlist directly related with a HTTP fields.
	# { HTTP_HEADER_FIELD : [wordlists] }
	m_wordlists_HTTP_fields = {
	    "Accept-Ranges"              : "accept-range",
	    "Server"                     : "banner",
	    "Cache-Control"              : "cache-control",
	    "Connection"                 : "connection",
	    "Content-Type"               : "content-type",
	    "WWW-Authenticate"           : "htaccess-realm",
	    "Pragma"                     : "pragma",
	    "X-Powered-By"               : "x-powered-by"
	}

	m_actions = {
	    'GET'        : { 'wordlist' : 'get_existing'       , 'protocol' : 'HTTP/1.1', 'method' : 'GET'      , 'payload': '/' },
	    'LONG_GET'   : { 'wordlist' : 'get_long'           , 'protocol' : 'HTTP/1.1', 'method' : 'GET'      , 'payload': '/%s' % ('a' * 200) },
	    'NOT_FOUND'  : { 'wordlist' : 'get_nonexisting'    , 'protocol' : 'HTTP/1.1', 'method' : 'GET'      , 'payload': '/404_NOFOUND__X02KAS' },
	    'HEAD'       : { 'wordlist' : 'head_existing'      , 'protocol' : 'HTTP/1.1', 'method' : 'HEAD'     , 'payload': '/' },
	    'OPTIONS'    : { 'wordlist' : 'options'            , 'protocol' : 'HTTP/1.1', 'method' : 'OPTIONS'  , 'payload': '/' },
	    'DELETE'     : { 'wordlist' : 'delete_existing'    , 'protocol' : 'HTTP/1.1', 'method' : 'DELETE'   , 'payload': '/' },
	    'TEST'       : { 'wordlist' : 'attack_request'     , 'protocol' : 'HTTP/1.1', 'method' : 'TEST'     , 'payload': '/' },
	    'INVALID'    : { 'wordlist' : 'wrong_method'       , 'protocol' : 'HTTP/9.8', 'method' : 'GET'      , 'payload': '/' },
	    'ATTACK'     : { 'wordlist' : 'wrong_version'      , 'protocol' : 'HTTP/1.1', 'method' : 'GET'      , 'payload': "/etc/passwd?format=%%%%&xss=\x22><script>alert('xss');</script>&traversal=../../&sql='%20OR%201;"}
	}

	m_wordlist_names = [
	    "accept-range.fdb",
	    "banner.fdb",
	    "cache-control.fdb",
	    "connection.fdb",
	    "content-type.fdb",
	    "etag-legth.fdb",
	    "etag-quotes.fdb",
	    "header-capitalafterdash.fdb",
	    "header-order.fdb",
	    "header-space.fdb",
	    "htaccess-realm.fdb",
	    "pragma.fdb",
	    "protocol-name.fdb",
	    "protocol-version.fdb",
	    "statuscode.fdb",
	    "statustext.fdb",
	    "vary-capitalize.fdb",
	    "vary-delimiter.fdb",
	    "vary-order.fdb",
	    "x-powered-by.fdb",
	    "options-public.fdb",
	    "options-allowed.fdb",
	    "options-delimited.fdb"
	]

	#
	# This dict has open handlers for files as forma:
	#
	# { ACTION : { DICT_NAME: FILE_HANDLE } }
	#
	# Example:
	# {
	#    'GET' :
	#    {
	#       'accept-range' : file( DIR/get_existing/accept-range.fdb )
	#       'banner'       : file( DIR/get_existing/banner.fdb )
	#       ...
	#    },
	#
	#    'LONG_GET' :
	#    {
	#       'accept-range' : file( DIR/get_long/accept-range.fdb )
	#       'banner'       : file( DIR/get_long/banner.fdb )
	#       ...
	#    },
	#
	#    ....
	# }
	m_wordlists = {}
	for l_k, l_w in m_actions.iteritems():
		m_wordlists[l_k] = {}
		for l_n in m_wordlist_names:

			# Create folder
			l_folder    = os.path.join(dst_dir, l_w["wordlist"])
			if not os.path.exists(l_folder):
				os.makedirs(l_folder)

			l_file_name = os.path.join(l_folder, l_n)
			l_w_name    = l_n.split(".")[0]
			m_wordlists[l_k][l_w_name] = l_file_name


	# For each host...
	for l_ip in IPs:

		# Store results for others HTTP params
		m_hostname            = l_ip[0]
		m_port                = l_ip[1]
		_debug                = verb

		print "    |-- Analyzing host: '%s:%s'" % (m_hostname, m_port)

		for l_action, v in m_actions.iteritems():
			if _debug:
				print "\n/--------------------------/"
			l_method      = v["method"]
			l_payload     = v["payload"]
			l_proto       = v["protocol"]
			l_wordlist    = m_wordlists[l_action]

			# Make the raw request
			l_raw_request = "%(method)s %(URI)s%(payload)s %(protocol)s\r\nHost: %(host)s\r\n\r\n" % (
				{
				    "method"     : l_method,
				    "payload"    : l_payload,
			        "URI"        : m_uri,
				    "protocol"   : l_proto,
				    "host"       : m_hostname,
				    "port"       : m_port
				}
			)

			if _debug:
				print "REQUEST:"
				print "======="
				print l_raw_request

			# Do the connection
			l_response = None
			try:
				l_response = get_HTTP( host            = m_hostname,
					                   port            = m_port,
					                   request_content = l_raw_request)

			except socket.error,e:
				m_errors += 1
				print "    [!] Not response for host '%s' with method '%s'. Message: %s" % (m_hostname, l_method, e.message)
				continue

			if not l_response:
				m_errors += 1
				print "    [!] Not response for host '%s' with method '%s'" % (m_hostname, l_method)
				continue


			# Get the banner to store
			l_banner = l_response["headers"].get("server")


			if _debug:
				print "RESPONSE:"
				print "========="
				print l_response["headers"]

			if _debug:
				print "ANALISYS:"
				print "========="

			# Analyze for each wordlist
			#

			#
			# =====================
			# HTTP directly related
			# =====================
			#
			#
			for l_http_header_name, l_header_wordlist in m_wordlists_HTTP_fields.iteritems():

				# Check if HTTP header field is in response
				l_curr_header_value = l_response["headers"].get(l_http_header_name)
				if not l_curr_header_value:
					continue

				# Store
				open(l_wordlist[l_header_wordlist], "a+").writelines("%s;%s\n" % (l_banner, l_curr_header_value))

			#
			# =======================
			# HTTP INdirectly related
			# =======================
			#
			#

			#
			# Status code
			# ===========
			#
			if l_response["statuscode"]:
				open(l_wordlist["statuscode"], "a+").writelines("%s;%s\n" % (l_banner, l_response["statuscode"]))

			#
			# Status text
			# ===========
			#
			if l_response["statustext"]:
				open(l_wordlist["statustext"], "a+").writelines("%s;%s\n" % (l_banner, l_response["statustext"]))

			#
			# Header space
			# ============
			#
			# Count the number of spaces between HTTP field name and their value, for example:
			# -> Server: Apache 1
			# The number of spaces are: 1
			#
			# -> Server:Apache 1
			# The number of spaces are: 0
			#
			try:
				l_http_value        = l_response["headers"].headers[0].split(":")[1] # get the value of first HTTP field
				l_spaces_num        = str(abs(len(l_http_value) - len(l_http_value.lstrip())))
				open(l_wordlist["header-space"], "a+").writelines("%s;%s\n" % (l_banner, l_spaces_num))

			except IndexError:
				print "index error header space"
				pass


			#
			# Header capitalafterdash
			# =======================
			#
			# Look for non capitalized first letter of field name, for example:
			# -> Content-type: ....
			# Instead of:
			# -> Content-Type: ....
			#
			l_valid_fields = [x for x in l_response["headers"].headers if "-" in x]
			if l_valid_fields:
				l_h = l_valid_fields[0]

				l_value = l_h.split("-")[1] # Get the second value: Content-type => type
				if l_value[0].isupper(): # Check first letter is lower
					if _debug:
						print "Capital after dash: 1"
					open(l_wordlist["header-capitalafterdash"], "a+").writelines("%s;%s\n" % (l_banner, "1"))


			#
			# Header order
			# ============
			#
			l_header_order      = ','.join(v.split(":")[0] for v in l_response["headers"].headers)
			open(l_wordlist["header-order"], "a+").writelines("%s;%s\n" % (l_banner, l_header_order))


			#
			# Protocol name
			# ============
			#
			# For a response like:
			# -> HTTP/1.0 200 OK
			#    ....
			#
			# Get the 'HTTP' value.
			#
			open(l_wordlist["protocol-name"], "a+").writelines("%s;%s\n" % (l_banner, l_response["protocol"]))

			#
			# Protocol version
			# ================
			#
			# For a response like:
			# -> HTTP/1.0 200 OK
			#    ....
			#
			# Get the '1.0' value.
			#
			open(l_wordlist["protocol-version"], "a+").writelines("%s;%s\n" % (l_banner, l_response["version"]))


			if l_response["headers"].get("etag"):
				l_etag_header       = l_response["headers"].get("etag")
				#
				# ETag length
				# ================
				#
				open(l_wordlist["etag-legth"], "a+").writelines("%s;%s\n" % (l_banner, str(len(l_etag_header))))

				#
				# ETag Quotes
				# ================
				#
				l_etag_striped          = l_etag_header.strip()
				if l_etag_striped.startswith("\"") or l_etag_striped.startswith("'"):
					open(l_wordlist["etag-quotes"], "a+").writelines("%s;%s\n" % (l_banner, l_etag_striped[0]))


			if l_response["headers"].get("vary"):
				l_vary_header       = l_response["headers"].get("vary")
				#
				# Vary delimiter
				# ================
				#
				# Checks if Vary header delimiter is something like this:
				# -> Vary: Accept-Encoding,User-Agent
				# Or this:
				# -> Vary: Accept-Encoding, User-Agent
				#
				l_var_delimiter     = ", " if l_vary_header.find(", ") else ","
				open(l_wordlist["vary-delimiter"], "a+").writelines("%s;%s\n" % (l_banner, l_var_delimiter))

				#
				# Vary capitalizer
				# ================
				#
				# Checks if Vary header delimiter is something like this:
				# -> Vary: Accept-Encoding,user-Agent
				# Or this:
				# -> Vary: accept-encoding,user-agent
				#
				l_vary_capitalizer  = str(0 if l_vary_header == l_vary_header.lower() else 1)
				open(l_wordlist["vary-capitalize"], "a+").writelines("%s;%s\n" % (l_banner, l_vary_capitalizer))

				#
				# Vary order
				# ================
				#
				# Checks order between vary values:
				# -> Vary: Accept-Encoding,user-Agent
				# Or this:
				# -> Vary: User-Agent,Accept-Encoding
				#
				open(l_wordlist["vary-order"], "a+").writelines("%s;%s\n" % (l_banner, l_vary_header))

			#
			# =====================
			# HTTP specific options
			# =====================
			#
			#
			if l_action == "HEAD" and l_response["headers"].get("allow"):
				#
				# HEAD Options
				# ============
				#
				l_option            = l_response["headers"].get("allow")
				open(l_wordlist["options-public"], "a+").writelines("%s;%s\n" % (l_banner, l_option))


			if l_action == "OPTIONS" or l_action == "INVALID" or l_action == "DELETE":
				if l_response["headers"].get("allow"):
					#
					# Options allow
					# =============
					#
					l_option            = l_response["headers"].get("allow")
					open(l_wordlist["options-public"], "a+").writelines("%s;%s\n" % (l_banner, l_option))

					#
					# Allow delimiter
					# ===============
					#
					l_var_delimiter     = ", " if l_option.find(", ") else ","
					open(l_wordlist["options-delimited"], "a+").writelines("%s;%s\n" % (l_banner, l_var_delimiter))

				if l_response["headers"].get("public"):
					#
					# Public response
					# ===============
					#
					l_option            = l_response["headers"].get("public")
					open(l_wordlist["options-public"], "a+").writelines("%s;%s\n" % (l_banner, l_option))

	return False if m_errors >= len(m_actions) else False


if __name__ == "__main__":
	main(sys.argv[1:])