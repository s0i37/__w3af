"""
blind_sqli_response_diff.py

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
import w3af.core.controllers.output_manager as om
import w3af.core.data.constants.severity as severity

from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.fuzzer.utils import rand_number
from w3af.core.controllers.misc.fuzzy_string_cmp import relative_distance_boolean
from w3af.core.controllers.misc.diff import diff
from w3af.core.controllers.exceptions import HTTPRequestException
from w3af.core.controllers.delay_detection.delay_mixin import DelayMixIn

from random import random
import string


class Blind_sqli_error(DelayMixIn):
    """
    This class tests for blind SQL injection bugs using difference between
    only two requests - valid string query (contains all printable chars, besides ' " \)
    and string leading to SQL syntax error. As a result will change body length, wait time
    or return code.

    :author: @s0i37
    """

    def __init__(self, uri_opener, freq, orig_response):
        # User configured variables
        self._uri_opener = uri_opener
        self._freq = freq
        self._orig_response = orig_response

    def is_injectable_maybe(self, mutant):
        """
        Check if "parameter" of the fuzzable request object is injectable or not

        @mutant: The mutant object that I have to inject to
        @param: A string with the parameter name to test

        :return: A vulnerability object or None if nothing is found
        """
        
        syntax_error = "1\"2'3\\"
        resp_len_orig = len( self._orig_response.get_body() )
        resp_code_orig = self._orig_response.get_code()

        mutant.set_token_value( syntax_error )
        (resp_len_invalid, resp_time_invalid, resp_code_invalid) = self._do_request(mutant)
        if resp_len_invalid == resp_len_orig and resp_code_invalid == resp_code_orig:
            return False

        mutant.set_token_value( self._get_random_letters(10) )
        (resp_len_valid, resp_time_valid, resp_code_valid) = self._do_request(mutant)
        if resp_len_valid == resp_len_orig and resp_code_valid == resp_code_orig:
            return False

        return True

    def debug(self, msg):
        om.out.debug( '[blind_sqli_errors]: ' + str(msg) )

    def _do_request(self, mutant):
        try:
            response = self._uri_opener.send_mutant( mutant, cache=False, timeout=10 )
            response_len = len( response.get_body() )
            response_time = response.get_wait_time()
            response_code = response.get_code()
            return ( response_len, response_time, response_code )
        except HTTPRequestException:
            self.debug("HTTPRequestException")
            return (-1, -1, -1)

    def _get_random_letters(self, maxlen=15):
        letters_chars = bytearray( string.letters )
        random_letters = ''
        for _ in xrange( maxlen ):
            random_letters += chr( letters_chars.pop( int( random() * len(letters_chars) ) ) )
        return random_letters.replace("'",'').replace('"','').replace('\\','')