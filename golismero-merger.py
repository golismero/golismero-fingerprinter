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


import argparse
import os
import sys
import shutil

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
def cmdline_parser():
	""""""

	m_examples = '''Examples:
	Merge 'ORIGINAL' with 'NEW'. Results will be merged into 'ORIGINAL':
	%(prog)s -d ORIGINAL -s NEW
	''' % { "prog" : " golismero-fingerprinter.py"}

	#----------------------------------------------------------------------
	# Command line parser using argparse
	m_parser = argparse.ArgumentParser(fromfile_prefix_chars="@",formatter_class=argparse.RawDescriptionHelpFormatter,  epilog=m_examples)
	m_parser.add_argument("-d", metavar="ORIGINAL", dest="src", help="original directory with wordlists", required=True)
	m_parser.add_argument("-s", metavar="NEW", dest="new", help="directory with new wordlists to be merged", required=True)

	return m_parser



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
	m_original_dir = os.path.abspath(P.src)
	m_new_dir      = os.path.abspath(P.new)
	if not os.path.exists(m_original_dir):
		print "[!] Directory '%s' not exits. Exiting..." % m_original_dir
		exit(1)
	if not os.path.exists(m_new_dir):
		print "[!] Directory '%s' not exits. Exiting..." % m_new_dir
		exit(1)

	# Run analyzer
	print "[*] Starting merging"
	merge(m_original_dir, m_new_dir)
	print ""
	print "[*] Done"

#----------------------------------------------------------------------
def merge(root_dst_dir, root_src_dir):
	""""""

	for src_dir, dirs, files in os.walk(root_src_dir):
		dst_dir = src_dir.replace(root_src_dir, root_dst_dir)
		if not os.path.exists(dst_dir):
			os.mkdir(dst_dir)
		for file_ in files:
			if not file_.endswith("fdb"):
				continue

			src_file = os.path.join(src_dir, file_)
			dst_file = os.path.join(dst_dir, file_)

			if os.path.exists(dst_file):
				# Check if content already exits
				l_dst_file = set((v.replace("\n", "") for v in open(dst_file,"rU").readlines()))
				l_src_file = set((v.replace("\n", "") for v in open(src_file,"rU").readlines()))

				# Find diferences
				l_diff     = ["%s\n" % v for v in (l_dst_file.union(l_src_file) - l_dst_file.intersection(l_src_file))]

				# Append differences
				open(dst_file,"a").writelines(l_diff)
			else:
				shutil.copy2(src_file, dst_dir)

			print ".",


if __name__ == "__main__":
	main(sys.argv[1:])