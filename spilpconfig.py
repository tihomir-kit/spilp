####################################################################
#==================================================================#
#   --------------    SPILP   CONFIG   OPTIONS    --------------   #
#==================================================================#
####################################################################
# Copyright 2011, Tihomir Kit (kittihomir@gmail.com)
# spilp is distributed under the terms of GNU General Public License v3
# A copy of GNU GPL v3 license can be found in LICENSE.txt or at http://www.gnu.org/licenses/gpl-3.0.html
#
# TO TURN OFF ANY OPTION, SET ITS VALUE TO 0
# TO TURN ON ANY OPTION, SET ITS VALUE TO 1




# -- put db in RAM - for smaller databases (faster) 
# Use if total ammount of log files is smaller than 2/3 of your total ammount of free RAM.
# :: set to ':memory:' to put the database to RAM 
#
# -- put db on HDD - for bigger databases (bigger) 
# Use if total ammount of log files is bigger than 2/3 of your total ammount of free RAM.
# :: set to '.tempdb' to put the database to HDD 
DB_STORAGE = ':memory:' 




# -- set to 1 to get hit counts per client IP --
# Results are sorted by number of hits.
CHECK_HITS_PER_IP = 1




# -- set to 1 to get the close IP's --
# Shows sorted IP's so attacks from the same region could be more easily identified.
CHECK_CLOSE_IPS = 1

# - minimum number of hits per IP to trigger logging --
# If an IP made less than CLOSE_IP_TRESHOLD number of hits, it will be ignored.
# Bigger CLOSE_IP_TRESHOLD value will show IP's with more activity, and will generate less output.
# Smaller CLOSE_IP_TRESHOLD value will show more IP's, and will generate more output.
# :: RECOMMENDED: 75-100
CLOSE_IP_TRESHOLD = 75




# -- set to 1 to get hit counts per agent --
# Results are sorted by number of hits.
CHECK_AGENTS = 1




# -- set to 1 to get method hits  --
# Results show hits for all methods except get.
CHECK_METHODS = 1




# -- set to 1 to get hits per text file --
# Results are sorted by number of hits.
CHECK_HITS_PER_TEXT_FILE = 1

# -- add or remove text filetype events to be logged --
# Only filetypes in DPTF_TYPES_TO_CHECK will be in output.
# :: RECOMMENDED filetypes: ('.pdf', '.doc', '.xls', '.ppt') - this will also look for .docx, .xlsx and .pptx files
DPTF_TYPES_TO_CHECK = ('.pdf', '.doc', '.xls', '.ppt')

# -- number of top hit files to get extended info --
# Only top DPTF_LINES_OUTPUT_LIMIT number of files will get extended information about 
# hits (date, time, ip's agents, status code...).
# :: for precise reports (when using filtering) - RECOMMENDED 10000 or higher
# :: for generic statistical reports - RECOMMENDED 50
DPTF_LINES_OUTPUT_LIMIT = 50




# -- set to 1 to get hits per web file --
# Results are sorted by number of hits.
CHECK_HITS_PER_WEB_FILE = 1

# -- add or remove web filetype events to be logged --
# Only filetypes in DPTF_TYPES_TO_CHECK will be in output.
# :: RECOMMENDED filetypes: ('.js', '.htm', '.asp') - this will also look for .html and .aspx files
DPWF_TYPES_TO_CHECK = ('.js', '.htm', '.asp')

# -- number of top hit files to get extended info --
# Only top DPWF_LINES_OUTPUT_LIMIT number of files will get extended information about 
# hits (date, time, ip's agents, status code...).
# :: for precise reports (when using filtering) - RECOMMENDED 10000 or higher
# :: for generic statistical reports - RECOMMENDED 50
DPWF_LINES_OUTPUT_LIMIT = 50




# -- set to 1 to get hit counts by HTTP status codes--
CHECK_STATUS_CODES_HITS = 1

# -- add or remove status codes to be examined in more detail --
# :: RECOMMENDED codes: ('400', '401', '403', '404', '405', '406', '416', '500', '501', '505')
STATUS_CODES_TO_CHECK = ('400', '401', '403', '404', '405', '406', '416', '500', '501', '505')

# -- maximum number of events for each HTTP status code that will allow logging -- 
# If there are too many hits for a certain HTTP status code, only STATUS_CODES_CODE_COUNT_TRESHOLD number 
# of events with the highest count will be in output. Higher number means more output and slower performance, 
# smaller nubmer means less output and faster performance.
# :: for precise reports (when using filtering) - RECOMMENDED 5000 or higher
# :: for generic statistical reports - RECOMMENDED 50
STATUS_CODES_CODE_COUNT_TRESHOLD = 50

# -- maximum number of events for HTTP status code event for each IP to trigger logging -- 
# If there are too many hits from an IP for a certain HTTP status code, only STATUS_CODES_EVENT_COUNT_TRESHOLD number 
# of events with the highest count will be in output. Higher number means more output and slower performance, 
# smaller nubmer means less output and faster performance.
# :: for precise reports (when using filtering) - RECOMMENDED 5000 or higher
# :: for generic statistical reports - RECOMMENDED 15
STATUS_CODES_EVENT_COUNT_TRESHOLD = 15

# -- minimum number of hits IP needs to make to trigger logging for that IP -- 
# If there are too many IP events to log, only events from IP's that made more than STATUS_CODES_IP_COUNT_TRESHOLD number 
# of hits will be in output. Higher number means less output and faster performance, smaller nubmer means more 
# output and slower performance.
# :: for precise reports (when using filtering) - RECOMMENDED 1
# :: for generic statistical reports - RECOMMENDED 50
STATUS_CODES_IP_COUNT_TRESHOLD = 50

# -- maximum number of hits per URI to trigger logging for that URI --
# If there are too many URI hits to log, only STATUS_CODES_URI_COUNT_TRESHOLD number of hits with the highest
# count will be in output. Higher number means more output and slower performance, smaller nubmer means 
# less output and faster performance.
# :: for precise reports (when using filtering) - RECOMMENDED 5000 or higher
# :: for generic statistical reports - RECOMMENDED 50
STATUS_CODES_URI_COUNT_TRESHOLD = 50




# -- set to 1 to turn on filtering by IP, date, agent... multiple parameters allowed --
# If a log line contains an expression from any of filter expressions, that line will or will not be further 
# processed depending on PARSING_FILTER_INCLUDE_EXCLUDE_SWITCH option. All other data will be dropped and 
# will not be a part of a generated report.
CHECK_PARSING_FILTER = 0

# -- set to 1 to use parsing filter to INCLUDE by expression --
# -- set to 0 to use parsing filter to EXCLUDE by expression --
# If set to 1, only results that match filter expressions will be included in reports.
# If set to 0, all results that match filter expressions will be excluded from reports.
PARSING_FILTER_INCLUDE_EXCLUDE_SWITCH = 1

# -- path and filename for *.txt file used for generating the parsing filter --
# Best placed in the same folder as spilp.py.
# Each line in the *.txt file is one filter expression.
PARSING_FILTER_FILE_NAME = "FILTERS.txt"




# -- set to 1 to turn on filtering by country --
# If you want to generate reports based on hits coming from a single country, use this option.
# If you are using this option, make sure to also set the COUNTRY_TO_CHECK option up.
# NOTE that if the CHECK_PARSING_FILTER option is set to 1, PARSING_FILTER_INCLUDE_EXCLUDE_SWITCH 
# option will decide whether events for the chosen country will get included or excluded.
CHECK_COUNTRY = 0

# -- name of a country to be checked upon --
# If a page hit is not coming from COUNTRY_TO_CHECK country, that event will get dropped
# and it will not be further processed.
COUNTRY_TO_CHECK = "Croatia"






