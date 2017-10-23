import string
import sys

from functools import wraps
from errno import ENOSPC

from w3af.core.controllers.plugins.output_plugin import OutputPlugin
from w3af.core.controllers.exceptions import ScanMustStopByKnownReasonExc
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.options.option_types import OUTPUT_FILE
import w3af.core.data.constants.severity as severity

import xlsxwriter


class trace(OutputPlugin):
    def __init__(self):
        OutputPlugin.__init__(self)
        self.output_file = './trace-http.xlsx'
        self._is_initialized = False

    def _init(self):
    	self._workbook = xlsxwriter.Workbook( self.output_file, {'strings_to_urls': False} )
        self._worksheet = self._workbook.add_worksheet("requests")
        format_default = self._workbook.add_format()
        format_bold = self._workbook.add_format( {"bold":1} )
        format_red = self._workbook.add_format()
        format_red.set_bg_color("red")
        self._formats = {
        	"DEFAULT": format_default,
        	"BOLD": format_bold,
        	"RED": format_red
        }

        self._worksheet.set_column("A:A", 50)
        self._worksheet.set_column("B:B", 40)
        self._worksheet.write( "A1", "uri", self._formats["BOLD"] )
    	self._worksheet.write( "B1", "data", self._formats["BOLD"] )
        self._worksheet.write( "C1", "code", self._formats["BOLD"] )
    	self._worksheet.write( "D1", "len", self._formats["BOLD"] )
    	self._worksheet.write( "E1", "time", self._formats["BOLD"] )

        self._row = 2
        self._is_initialized = True

    def do_nothing(self, *args, **kwargs):
        pass

    debug = vulnerability = do_nothing
    information = error = console = log_enabled_plugins = do_nothing

    def log_http(self, request, response, new_line=True):
    	if not self._is_initialized:
    		self._init()

    	uri = request.get_full_url()
    	data = request.get_data()
        code = response.get_code()
    	_len = len( response.get_body() )
    	_time = response.get_wait_time()

    	self._worksheet.write("A%d" % self._row, uri)
    	self._worksheet.write("B%d" % self._row, data)
        self._worksheet.write("C%d" % self._row, code, self._formats["RED"] if code >= 500 else self._formats["DEFAULT"] )
    	self._worksheet.write("D%d" % self._row, _len)
    	self._worksheet.write("E%d" % self._row, _time, self._formats["RED"] if _time > 1 else self._formats["DEFAULT"] )

    	self._row += 1
    	
    def end(self):
    	if self._is_initialized:
    		self._workbook.close()

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin exports all requests information
        to the given XLSX file.

        One configurable parameter exists:
            - output_file
        """

    def set_options(self, option_list):
        """
        Sets the Options given on the OptionList to self. The options are the
        result of a user entering some data on a window that was constructed
        using the XML Options that was retrieved from the plugin using
        get_options()

        :return: No value is returned.
        """
        self.output_file = option_list['output_file'].get_value()

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()

        d = 'The name of the output file where the requests information are be saved'
        o = opt_factory('output_file', self.output_file, d, OUTPUT_FILE)
        ol.add(o)

        return ol