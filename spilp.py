#############################################################
#===========================================================#
#   Simple Python IIS Log Parser (SPILP)  -- Python3.2 --   #
#===========================================================#
#############################################################
# Copyright 2011, Tihomir Kit (kittihomir@gmail.com)
# spilp is distributed under the terms of GNU General Public License v3
# A copy of GNU GPL v3 license can be found in LICENSE.txt or at http://www.gnu.org/licenses/gpl-3.0.html
#
# SPILP config file  ==>>  spilpconfig.py
# last modification - 12/09/11

from collections import defaultdict
from itertools import filterfalse
from time import gmtime, strftime, mktime
from spilpconfig import *
import operator
import pygeoip
import sqlite3
import shutil
import codecs
import socket
import os
import re


# ---- dump the data into a file ---- #
def dumpToFile(file_name, data_dump):
	file_name = "generated_reports/" + file_name
	data_file = open(file_name, 'w')
	data_file.write(str(data_dump))
	data_file.close()


# ---- remove leftover temp files and folders ---- #
def cleanUp():
	if os.path.exists("__pycache__"):
		shutil.rmtree("__pycache__")
	if os.path.exists(".tempdb"):
		os.remove(".tempdb")	


# ---- add dates and extension to filenames ---- #	
def setFileName(file_name):	
	date = gmtime()
	file_name += strftime("_%y%m%d", date) + ".txt"
	return file_name


# ---- if filtering is turned on, initialize filter ---- #
def initializeFilters():
	global country_filter
	filter = []
	
	# converts the filter file into a list for later use
	if CHECK_PARSING_FILTER:
		with open(PARSING_FILTER_FILE_NAME, 'r', encoding='utf-8', errors='ignore') as filter_lines:		
			for line in filter_lines:
				line = line.strip()
				
				# if there is an IP range in FILTERS.txt, generate the list and append it
				if line.startswith("$$.ip_range"):
					ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
					ip_range = ipRange(ips[0], ips[1])
					for ip in ip_range:
						filter.append(ip)
					continue 

				filter.append(line)

	return filter	


# ---- generates a list of IP addresses based on given range ---- #
def ipRange(start_ip, end_ip):
	start = list(map(int, start_ip.split(".")))
	end = list(map(int, end_ip.split(".")))
	temp = start
	ip_range = []
	
	# increments leading IP octets on overflow
	ip_range.append(start_ip)
	while temp != end:
		start[3] += 1
		for i in (3, 2, 1):
			if temp[i] == 256:
				temp[i] = 0
				temp[i-1] += 1
		ip_range.append(".".join(map(str, temp)))	
		
	return ip_range
	

# ---- return short HTTP status code description ---- #
def httpCodeDescription(sc_status):
	result = "HTTP Code " + str(sc_status) + " ("

	# dictionary of HTTP status codes
	codes = { 
		'200': "OK", 
		'206': "Partial content",
		'301': "Moved permanently",
		'302': "Found",
		'304': "Not modified",
		'400': "Bad request",
		'401': "Unauthorized",
		'403': "Forbidden",
		'404': "Not found",
		'405': "Method not allowed",
		'406': "Not acceptable",
		'416': "Requested range not satisfiable",
		'500': "Internal server error",
		'501': "Not implemented",
		'502': "Bad gateway",
		'503': "Service unavailable",
		'505': "HTTP version not supported"
	}	
	
	if sc_status in codes:
		result += codes[sc_status] + ")"
	else:
		result += "NO HTTP STATUS CODE DESCRIPTION - check the code meaning on the Internet)"
	
	return result
	
	
# ---- get hit counts per client IP ---- #
def hitsPerIp(file_name):
	file_name = setFileName(file_name)
	file_output = ""
	i = 1
	
	print("::\n:: Preparing", file_name)
	file_output += "Number of hits made per IP (sorted)\n\n"
	
	# sorts by IP hit counts
	for c_ip, count in sorted(ip_count.items(), key=operator.itemgetter(1), reverse=True):
		country_name = gio.country_name_by_addr(c_ip)
		if country_name == "":
			country_name = "-"	
		file_output = file_output + str(i) + ". (" + str(count) + " hits) --- " + str(c_ip) + "  (" + country_name + ")\n"
		i += 1
		
	dumpToFile(file_name, file_output)
	print(":: => report dumped")

	
# ---- get hit counts for "close" IP addresses ---- #	
def closeIps(file_name, CLOSE_IP_TRESHOLD):
	file_name = setFileName(file_name)
	file_output = ""
	i = 1
	
	print("::\n:: Preparing", file_name)
	file_output += "Close IP addresses (with more than " + str(CLOSE_IP_TRESHOLD) + " hits per IP)\n\n"
	
	# sorts by IP, so 'close' IP's could be identified
	for c_ip, count in sorted(ip_count.items(), key=lambda item: socket.inet_aton(item[0])): 
		# if less hits than CLOSE_IP_TRESHOLD (per IP address), then gtfo
		if count > CLOSE_IP_TRESHOLD:		
			country_name = gio.country_name_by_addr(c_ip)
			if country_name == "":
				country_name = "-"
			file_output = file_output + str(i) + ". (" + str(count) + " hits) --- " + str(c_ip) + " (" + country_name + ")\n"
			i += 1

	dumpToFile(file_name, file_output)
	print(":: => report dumped")


# ---- get agent counts ---- #
def agentHits(file_name):
	file_name = setFileName(file_name)
	file_output = ""
	i = 1
	
	print("::\n:: Preparing", file_name)
	file_output += "Agent hits\n\n"
	
	# sorts agents by counts (descending)
	for cs_user_agent, count in sorted(agent_count.items(), key=operator.itemgetter(1), reverse=True):
		file_output += str(i) + ". (" + str(count) + " hits) --- " + str(cs_user_agent) + "\n"	
		i += 1
		
	dumpToFile(file_name, file_output)
	print(":: => report dumped")

	
# ---- get cs-methods ---- #
def methodHits(file_name):
	file_name = setFileName(file_name)
	file_output = ""
	i = 1
	
	print("::\n:: Preparing", file_name)	
	file_output += "CS-Method hits"
	
	# sorts methods by counts
	for method, count in sorted(hits_by_method.items(), key=operator.itemgetter(1), reverse=True):
		# skips the GET method
		if method == "GET":
			continue
		
		file_output += "\n\n" + str(i) + ". Method: " + str(method) + "\n:: " + str(count) + " hits\n\n"
		i += 1
		
		# filters db data and outputs rows
		rows = db_cursor.execute("SELECT date, time, c_ip, cs_method, s_port, cs_uri_stem, cs_user_agent, sc_status FROM hits_by_extension_table WHERE cs_method = '" + method + "'")
		for row in rows:
			file_output += "    "
			for element in row:
				file_output += str(element)	+ " "
			file_output += "\n"
		
	dumpToFile(file_name, file_output)
	print(":: => report dumped")
	

# ---- get hit counts by status ---- #
def statusHits(file_name):
	file_name = setFileName(file_name)
	status_ip_count = defaultdict(int)
	status_uri_count = defaultdict(int)
	file_output = ""
	i = 1
	
	print("::\n:: Preparing", file_name)
	file_output += "Number of hits by HTTP status code\nDetailed output for -> " + str(STATUS_CODES_TO_CHECK) + "\n\n"
	
	# sorts HTTP status codes
	for sc_status, code_count in sorted(hits_by_status_count.items(), key=operator.itemgetter(1), reverse=True):
		file_output += "\n" + str(i) + ". " + httpCodeDescription(sc_status) + "\n:: " + str(code_count) + " hits\n"
		
		# proceed if HTTP status code is in STATUS_CODES_TO_CHECK
		if sc_status in STATUS_CODES_TO_CHECK:
			status_ip_rows = db_cursor.execute("SELECT c_ip FROM hits_by_extension_table WHERE sc_status = '" + sc_status + "'")	
			status_ip_count.clear()
			for ip_status in status_ip_rows:
				status_ip_count[ip_status[0]] += 1 #count by IP
			
			event_count = 0			
			# sorts hits by IP addresses
			for c_ip, ip_count in sorted(status_ip_count.items(), key=operator.itemgetter(1), reverse=True):
				event_count += 1
				if (event_count >= STATUS_CODES_EVENT_COUNT_TRESHOLD or ip_count < STATUS_CODES_IP_COUNT_TRESHOLD) and code_count >= STATUS_CODES_CODE_COUNT_TRESHOLD: 
					break
				file_output += "\n    " + str(c_ip) + " (" + gio.country_name_by_addr(c_ip) + ") --- " + str(ip_count) + " hits\n"
				
				status_uri_rows = db_cursor.execute("SELECT cs_uri_stem FROM hits_by_extension_table WHERE sc_status = '" + sc_status + "' AND c_ip ='" + c_ip + "'")
				status_uri_count.clear()
				for uri_status in status_uri_rows:
					status_uri_count[uri_status[0]] += 1 #count by URI
				
				uri_count_check = 0
				# sorts hits by URI
				for cs_uri_stem, uri_count in sorted(status_uri_count.items(), key=operator.itemgetter(1), reverse=True):
					file_output += "        " + str(cs_uri_stem) + " --- " + str(uri_count) + " hits\n"
					uri_count_check += 1
					if uri_count_check >= STATUS_CODES_URI_COUNT_TRESHOLD:
						break
			file_output += "\n"
		else:
			file_output += "\n    No detailed output for events of this status code because the status is not listed in STATUS_CODES_TO_CHECK option in spilpconfig.py\n\n"
		i += 1
		
	dumpToFile(file_name, file_output)
	print(":: => report dumped")
	
	
# ---- get hit counts per file ---- #		
def hitsByExtension(file_name, extensions_to_check, limit):
	file_name_extended = setFileName(file_name + "Extended")
	file_name = setFileName(file_name)
	file_output_extended = ""
	file_output = ""
	i = 0
	
	# fetch the data from sqlite db, and convert it from an iterator to a list
	db_rows = db_cursor.execute("SELECT * FROM hits_by_extension_table")	
	db_rows = list(db_rows)
	
	print("::\n:: Preparing", file_name, "\n:: Extensions to check - {0}".format(extensions_to_check))	
	file_output += "Number of times files have been hit (sorted)\n\n"
	file_output_extended += "Number of times files have been hit (sorted and extended with additional information)\n"
	file_output_extended += "Detailed output for -> " + str(extensions_to_check) + "\n"
	file_output_extended += "Output format:  DATE  TIME  CLIENT_IP  METHOD  PORT  AGENT  STATUS_CODE\n\n"
	
	# sort by hits (groups by file extensions)
	for cs_uri_stem, count in sorted(hits_by_extension_count.items(), key=operator.itemgetter(1), reverse=True):
		if cs_uri_stem.endswith(extensions_to_check):
			full_path = str(cs_uri_stem.encode('utf-8', 'backslashreplace'))[2:-1]
			file_output += str(i + 1) + ". (" + str(count) + " hits) --- " + full_path + "\n"	
			
			#time_bla = gmtime()
			#print(strftime("%H:%M:%S", time_bla), full_path.encode('utf-8', 'backslashreplace'))	
			
			# more detailed file output
			file_output_extended += str(i + 1) + ". (" + str(count) + " hits) --- " + full_path + "\n\n"
			for row in db_rows:
				if row[5] == full_path:
					file_output_extended += "    "
					for element in row: 
						if element != full_path:
							file_output_extended += element + "  "				
					file_output_extended += "\n"
			file_output_extended += "\n\n"
			
			# stop iterating at output_line_limit
			i += 1	
			if i == limit:	
				break	
				
	dumpToFile(file_name, file_output)	
	dumpToFile(file_name_extended, file_output_extended)
	print(":: => report dumped")
	
	
# ---- split each logline into multiple variables, populate dictionaries and db ---- #		
def splitLogline(log_line):
	# IIS log fields layout
	date, time, s_sitename, s_ip, cs_method, cs_uri_stem, cs_uri_query, s_port, cs_username, c_ip, cs_user_agent, sc_status, sc_substatus, sc_win32_status = log_line.split(" ")
	
	# filter by country
	if CHECK_COUNTRY:
		if COUNTRY_TO_CHECK != gio.country_name_by_addr(c_ip):
			return
	
	# populating dictionaries and sqlite3 db
	ip_count[c_ip] += 1
	agent_count[cs_user_agent] += 1
	hits_by_method[cs_method] += 1
	hits_by_status_count[sc_status] += 1
	hits_by_extension_count[cs_uri_stem] += 1	
	
	db_cursor.execute(
		"INSERT INTO hits_by_extension_table(date, time, c_ip, cs_method, s_port, cs_uri_stem, cs_user_agent, sc_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		(date, time, c_ip, cs_method, s_port, cs_uri_stem, cs_user_agent, sc_status)
	)


# ---- fetch log files from current folder and its 1st level subfolders ---- #		
def fetchData(folder_name):	
	global total_events
		
	# look for folders in current folder
	print("\n\nENTERING FOLDER: ", end="")
	if folder_name == "":
		print(os.getcwd())
		folder_name = "."
	else: 
		print("{0}\{1}".format(os.getcwd(), folder_name))
		
	# for each log file found, filter data and populate dicts and db
	for file_name in os.listdir(folder_name):
		if ".log" in file_name:
			print("::\n:: Gathering data from", file_name)
			file_path = folder_name + "/" + file_name

			with open(file_path, 'r', encoding='utf-8', errors='ignore') as log_lines:
				# skip the log line if it does not contain one of the values from PARSING_FILTER
				if CHECK_PARSING_FILTER:
					# exclusion filter turned on 
					if PARSING_FILTER_INCLUDE_EXCLUDE_SWITCH == 0:
						for log_line in filterfalse(lambda log_line: log_line.startswith("#"), log_lines):
							if any(filter in log_line for filter in parsing_filter):
								continue
							else:
								splitLogline(log_line)
								total_events += 1														
					# inclusion filter turned on			
					elif PARSING_FILTER_INCLUDE_EXCLUDE_SWITCH == 1:
						for log_line in filterfalse(lambda log_line: log_line.startswith("#"), log_lines):						
							if any(filter in log_line for filter in parsing_filter):
								splitLogline(log_line)
								total_events += 1		
				else:
					for log_line in filterfalse(lambda log_line: log_line.startswith("#"), log_lines):
						splitLogline(log_line)
						total_events += 1
			
			db_connection.commit()				
			print(":: => done.")			
	print("::\n:: exiting folder...")

	

############################################################	
### ----------------------- MAIN ----------------------- ###
############################################################
time_start = gmtime()
print("\n\nJob started at", strftime("%H:%M:%S", time_start))

# check/create a directory for dumping reports
if not os.path.exists("generated_reports"):
	os.makedirs("generated_reports")

# initialize vars
parsing_filter = initializeFilters()
gio = pygeoip.GeoIP("GeoIP.dat")
hits_by_extension_list = []
log_lines = []
folder_name = ""
total_events = 0

# initialize sqlite DB
db_connection = sqlite3.connect(DB_STORAGE)
db_cursor = db_connection.cursor()
db_cursor.execute("CREATE TABLE IF NOT EXISTS hits_by_extension_table(date, time, c_ip, cs_method, s_port, cs_uri_stem, cs_user_agent, sc_status)")
db_connection.commit()

# initialize empty defaultdicts 
ip_count = defaultdict(int)
agent_count = defaultdict(int)
hits_by_method = defaultdict(int)
hits_by_status_count = defaultdict(int)
hits_by_extension_count = defaultdict(int)

# split raw log data (events) through multiple variables
fetchData(folder_name)
for folder_name in os.listdir():
	if os.path.isdir(folder_name):
		fetchData(folder_name)					
		
# dumping time! :D
print("\n\nPROCESSING", total_events, "log events...")
closeIps("closeIps", CLOSE_IP_TRESHOLD) if CHECK_CLOSE_IPS else 0	
hitsPerIp("hitsPerIp") if CHECK_HITS_PER_IP else 0
statusHits("hitsByStatus") if CHECK_STATUS_CODES_HITS else 0
hitsByExtension("documentDownloads", DPTF_TYPES_TO_CHECK, DPTF_LINES_OUTPUT_LIMIT) if CHECK_HITS_PER_TEXT_FILE else 0
hitsByExtension("webFilesHits", DPWF_TYPES_TO_CHECK, DPWF_LINES_OUTPUT_LIMIT) if CHECK_HITS_PER_WEB_FILE else 0 
agentHits("agentHits") if CHECK_AGENTS else 0
methodHits("methodHits") if CHECK_METHODS else 0

db_connection.close()
cleanUp()

time_stop = gmtime()
time_diff_seconds = mktime(time_stop) - mktime(time_start)
time_diff_minutes = time_diff_seconds / 60	
print("::\n:: done...\n\n\nTime elapsed: {0:0.1f} minutes ({1}s)".format(time_diff_minutes, time_diff_seconds), "\nJob finished at", strftime("%H:%M:%S", time_stop), "\n\n")
input("\nPres Enter to continue...\n\n\n\n\n\n\n\n")