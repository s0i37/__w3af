"""
text_file.py

Copyright 2006 Andres Riancho

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
import time
import os

import w3af.core.data.kb.config as cf
import w3af.core.data.constants.severity as severity
import w3af.core.controllers.output_manager as om

from w3af.core.controllers.plugins.output_plugin import OutputPlugin
from w3af.core.controllers.exceptions import BaseFrameworkException
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_types import OUTPUT_FILE
from w3af.core.data.options.option_list import OptionList

import sqlite3

class test(OutputPlugin):
    """
    Prints body_len and resp_time to a sqlite database.

    :author: @s0i37
    """

    def __init__(self):
        OutputPlugin.__init__(self)

        # User configured parameters
        self._output_db_name = '~/output.db'
        self.verbose = True

        # Internal variables
        self._initialized = False

        # File handlers
        self._db = None
        self._sql = None

        # XXX Only set '_show_caller' to True for debugging purposes. It
        # causes the execution of potentially slow code that handles
        # with introspection.
        self._show_caller = False

    def _init(self):
        self._output_db_name = os.path.expanduser(self._output_db_name)
        self._is_need_init_db = not os.path.exists( self._output_db_name )
        self._db = sqlite3.connect( self._output_db_name, check_same_thread=False )
        self._sql = self._db.cursor()
        if self._is_need_init_db:
            self._init_db()

    def _init_db(self):
        self._sql.execute("create table resp(id integer primary key AUTOINCREMENT, uri text, body_len integer, resp_time float)")
        self._db.commit()

    def save_db(self, uri, body_len, resp_time):
        try:
            self._sql.execute( "insert into resp(uri,body_len,resp_time) values(?,?,?)", ( str(uri),body_len,resp_time) )
            self._db.commit()
        except Exception as e:
            print str(e)

    def console(self, message, new_line=True, obj=object()):
        """
        This method is called from the output object. The output object was
        called from a plugin or from the framework. This method should take an
        action for informational messages.
        """
        uri = obj.get_uri()
        body_len = len( obj.get_body() )
        resp_time = obj.get_wait_time()
        print "%-050s   %08d   %.04f" % (uri, body_len, resp_time)
        self.save_db(uri, body_len, resp_time)

    def debug(self, message, new_line=True):
        pass

    def error(self, message, new_line=True):
        pass

    def information(self, message, new_line=True):
        pass

    def end(self):
        print '[done]'
        if self._db is not None:
            self._db.close()


    def set_options(self, option_list):
        """
        Sets the Options given on the OptionList to self. The options are the
        result of a user entering some data on a window that was constructed
        using the XML Options that was retrieved from the plugin using
        get_options()

        This method MUST be implemented on every plugin.

        :return: No value is returned.
        """
        self.verbose = option_list['verbose'].get_value()
        self._output_db_name = option_list['output_file'].get_value()
        self._init()

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()

        d = 'Enable if verbose output is needed'
        o = opt_factory('verbose', self.verbose, d, 'boolean')
        ol.add(o)

        d = 'File name where this plugin will write to'
        o = opt_factory('output_file', self._output_db_name, d, OUTPUT_FILE)
        ol.add(o)

        return ol


    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin writes the framework messages to a text file.

        Four configurable parameters exist:
            - output_db_file
            - verbose
        """
