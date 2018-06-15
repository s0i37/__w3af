"""
console.py

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
import string
import sys

from functools import wraps
from errno import ENOSPC
from urllib import unquote

from w3af.core.controllers.plugins.output_plugin import OutputPlugin
from w3af.core.controllers.exceptions import ScanMustStopByKnownReasonExc
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.constants.severity import HIGH, MEDIUM, LOW, INFORMATION
from w3af.core.data.fuzzer.mutants.mutant import Mutant

from colorama import Fore, Back

def catch_ioerror(meth):
    """
    Function to decorate methods in order to catch IOError exceptions.
    """
    @wraps(meth)
    def wrapper(self, *args, **kwargs):
        try:
            return meth(self, *args, **kwargs)
        except IOError as (errno, strerror):
            if errno == ENOSPC:
                msg = 'No space left on device'
                raise ScanMustStopByKnownReasonExc(msg)

    return wrapper

def chksum(content=''):
    summ = 0
    for ch in content:
        summ += ord(ch)
    return "%04x" % (summ % 0x10000)

class console(OutputPlugin):
    """
    Print messages to the console.

    :author: Andres Riancho (andres.riancho@gmail.com)
    """
    def __init__(self):
        OutputPlugin.__init__(self)

        # User configured setting
        self.verbose = False

    def _make_printable(self, a_string):
        a_string = str(a_string)
        a_string = a_string.replace('\n', '\n\r')
        return ''.join(ch for ch in a_string if ch in string.printable)

    def _print_to_stdout(self, message, newline):
        to_print = self._make_printable(message)
        if newline:
            to_print += '\r\n'
        sys.stdout.write(to_print)
        sys.stdout.flush()

    @catch_ioerror
    def debug(self, message, new_line=True):
        """
        This method is called from the output object. The output object was
        called from a plugin or from the framework. This method should take
        an action for debug messages.
        """
        if self.verbose:
            print Fore.LIGHTBLACK_EX + message + Fore.RESET

    def log_http(self, request, response, new_line=True):
        code = int( response.get_code() )
        size = len( response.get_body() )
        time = response.get_wait_time()
        #code_str = ( Fore.LIGHTRED_EX if code >= 500 else Fore.LIGHTYELLOW_EX ) + str(code)
        #size_str = Fore.LIGHTYELLOW_EX + str(size)
        #time_str = Fore.LIGHTYELLOW_EX + "%.03f" % time
        code_str = str(code)
        size_str = str(size)
        time_str = "%.03f" % time
        uri = unquote( request.get_full_url() )
        inject_point = None
        if isinstance(request._from, Mutant):
            inject_point = request._from.get_token_value()
            param = request._from.get_token_name()
        if inject_point:
            uri = uri.replace( "%s=%s"%(param,inject_point), Fore.LIGHTRED_EX + "%s=%s"%(param,inject_point) + Fore.LIGHTGREEN_EX )
        print Fore.LIGHTGREEN_EX + "{method} {uri}".format( method=request.get_method(), uri=uri ) ,
        print Fore.LIGHTYELLOW_EX + "  [{code}] [{size}] [{chksum}] [{time}]".format( code=code_str, size=size_str, chksum=chksum( response.get_body() ), time=time_str ),
        if request.get_data():
            print Fore.GREEN
            postdata = unquote( request.get_data() )
            if inject_point:
                postdata = postdata.replace( "%s=%s"%(param,inject_point), Fore.LIGHTRED_EX + "%s=%s"%(param,inject_point) + Fore.LIGHTGREEN_EX )
            print postdata
        print Fore.RESET

    def information(self,message):
        print Fore.CYAN + message + Fore.RESET


    def vulnerability(self, message, new_line=True, severity=MEDIUM):
        if severity == HIGH:
            print Fore.WHITE + Back.RED + message + Fore.RESET + Back.RESET
        elif severity == MEDIUM:
            print Fore.WHITE + Back.YELLOW + message + Fore.RESET + Back.RESET
        elif severity == LOW:
            print Fore.WHITE + Back.GREEN + message + Fore.RESET + Back.RESET
        elif severity == INFORMATION:
            print Fore.WHITE + Back.BLUE + message + Fore.RESET + Back.RESET

    @catch_ioerror
    def _generic(self, message, new_line=True, severity=None):
        """
        This method is called from the output object. The output object was
        called from a plugin or from the framework. This method should take
        an action for all messages except from debug ones.
        """
        self._print_to_stdout(message, new_line)

    console = _generic

    def error(self, message):
        print Fore.RED + message + Fore.RESET

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin writes the framework messages to the console.

        One configurable parameter exists:
            - verbose
        """

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

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()
        d = 'Enables verbose output for the console'
        o = opt_factory('verbose', self.verbose, d, 'boolean')
        ol.add(o)

        return ol
