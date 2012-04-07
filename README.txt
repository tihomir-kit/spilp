# Copyright 2011, Tihomir Kit (kittihomir@gmail.com)
# spilp is distributed under the terms of GNU General Public License v3
# A copy of GNU GPL v3 license can be found in LICENSE.txt or at http://www.gnu.org/licenses/gpl-3.0.html


	Simple Python IIS log parser (spilp) is a simple Python parser that takes IIS logs, 
	parses them and creates statistical reports which can be used to discover unusual 
	IP activity more easily. 


 1. Features
 2. Usage
 3. Download links


 
1. Features
--------------------------------------------------------
 - extracts a list of IP addresses with number of hits they made sorted by number of hits
 - extracts a list of "close" IP addresses that made a certain number of hits
 - extracts a list of user agents sorted by number of hits
 - extracts a list of cs-method hits (GET method excluded)
 - extracts a list of file hits sorted by number of hits
   - .pdf, .doc, .xls, .ppt (document files)
   - .js, .htm, .asp (web files)
 - extracts extended information for document and web file hits
   - includes timestamps, client IP addresses, methods, ports, user agent details and http status codes
 - extracts a list of "unusual" http status code hits sorted by number of hits
   - client IP address list
   - a list of files hit by an IP and number of hits for that file
 - filtering results (include or exclude filtering - works in "either-or" way)
   - ability to auto-generate an IP range list as a filter
 - reverse DNS country lookup using MaxMinds GeoIP country downloadable database 
   - additional info in certain reports
   - filtering results by country of origin (as a separate filtering option using spilpconf.py file) 
 - ability to process large amount of IIS log files
 - CONFIG file for performance and output tweaking

 

2. Usage
--------------------------------------------------------
Spilp is written in python3.2 so you will need that installed (if not using Windows binary
version).

Spilp requires pygeoip python module to work properly. It also requires GeoIP country free 
database (find links below). After downloading GeoIP.dat.gz from MaxMind website, extract 
the archive, and put GeoIP.dat database into the same folder as spilp.py. GeoIP country 
database binary should be updated every once in a while to get the latest country IP ranges. 

To tweak the amount of output and/or performance, edit spilpconfig.py.
Note that if you have large amounts of log files (more than 2/3 of your free amount of RAM), 
you must change DB_STORAGE option to ".tempdb".

IIS log files will be automatically parsed if they are in spilp root directory or in any 1st
level subdirectory residing in spilp root directory.

Spilp currently works with default IIS log format meaning that it uses the following IIS fields:
date time s-sitename s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status

If you are using a different IIS log format, you will need to add/remove certain variables in
splitLogLine() function in spilp.py (left part of the line that contains "log_line.split").
Be careful when doing so though, because you must have the same number of variables there
as you have fields in your IIS logs and they must be in same order. Keeping variable names
the same is recommended unless you know what you are doing.

To use an IP range list for filtering, use the following syntax:
$$.ip_range(192.168.1.1 - 192.170.127.234)
and put that line into your FILTERS.txt file as you would do with any other filter expression. 

Windows users can use spilp.exe binary. In that case there is no need for Python and pygeoip 
to be installed on the machine. GeoIP country database still needs to be downloaded from
MaxMinds website and it needs to be put into the same folder where spilp.exe is located.



3. Download links
--------------------------------------------------------
pygeoip: http://code.google.com/p/pygeoip
GeoIP country: http://www.maxmind.com/app/geolitecountry
GeoIP database: http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz


