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

    def __init__(self, uri_opener):
        # User configured variables
        self._eq_limit = 0.8
        self.uri_opener = uri_opener

    def set_eq_limit(self, eq_limit):
        """
        Most of the equal algorithms use a rate to tell if two responses
        are equal or not. 1 is 100% equal, 0 is totally different.

        :param eq_limit: The equal limit to use.
        """
        self._eq_limit = eq_limit

    def is_injectable(self, mutant):
        """
        Check if "parameter" of the fuzzable request object is injectable or not

        @mutant: The mutant object that I have to inject to
        @param: A string with the parameter name to test

        :return: A vulnerability object or None if nothing is found
        """

        self.mutant = mutant
        vuln = self._check_response_len()
        if not vuln:
            vuln = self._check_response_time()
        return vuln

    def debug(self, msg):
        om.out.debug( '[blind_sqli_errors]: ' + str(msg) )

    def _delta_random_responses_len(self):
        self.mutant.set_token_value( self._get_random_letters() )
        try:
            random_response1 = self.uri_opener.send_mutant( self.mutant, cache=False, timeout=10 )
        except HTTPRequestException:
            self.debug("HTTPRequestException")
            return -1

        self.mutant.set_token_value( self._get_random_letters() )
        try:
            random_response2 = self.uri_opener.send_mutant( self.mutant, cache=False, timeout=10 )
        except HTTPRequestException:
            self.debug("HTTPRequestException")
            return -1

        return abs( len( random_response1.get_body() ) - len( random_response2.get_body() ) )

    def _check_response_len(self):
        delta_len = self._delta_random_responses_len()
        self.debug("random responses delta_len %d" % delta_len)
        if delta_len:
            # if two random valid requests returns various response length -
            # we do not perform this check
            return

        is_vuln = False
        query = self._get_random_letters()
        self.mutant.set_token_value(query)
        try:
            random_response = self.uri_opener.send_mutant( self.mutant, cache=False, timeout=10 )
        except HTTPRequestException:
            # if response do not receive on normal request - stop
            self.debug("HTTPRequestException")
            return

        syntax_error = query[:-3] + "\"'\\"
        self.mutant.set_token_value(syntax_error)
        try:
            syntax_error_response = self.uri_opener.send_mutant( self.mutant, cache=False, timeout=10 )
            random_response_len = len( random_response.get_body() )
            syntax_error_response_len = len( syntax_error_response.get_body() )
            delta_len = abs( random_response_len - syntax_error_response_len )
            self.debug("responses delta_len %d (%d) (%d)" % (delta_len, random_response_len, syntax_error_response_len) )
            # if delta_len > 1% of previous len - may be sqlinj
            if delta_len > len( random_response.get_body() ) / 100:
                is_vuln = True
        except HTTPRequestException:
            # if response do not receive - may be sqlinj
            self.debug("HTTPRequestException")
            is_vuln = True

        if is_vuln:
            response_ids = [random_response.id,
                            syntax_error_response.id]
            
            desc = 'Blind SQL injection at: "%s", using'\
                   ' HTTP method %s. The injectable parameter may be: "%s"'
            desc = desc % (self.mutant.get_url(),
                           self.mutant.get_method(),
                           self.mutant.get_token_name())
            
            v = Vuln.from_mutant('Blind SQL injection vulnerability', desc,
                                 severity.HIGH, response_ids, 'blind_sqli',
                                 self.mutant)
            
            om.out.debug(v.get_desc())

            v['valid_html'] = random_response.get_body()
            v['error_html'] = syntax_error_response.get_body()
            return v

    def _check_response_time(self):
        is_vuln = False
        query = self._get_random_letters()
        self.mutant.set_token_value( query )
        original_wait_time = self.get_original_time()

        syntax_error = query[:-3] + "\"'\\"
        self.mutant.set_token_value(syntax_error)
        try:
            delta_time = -1
            syntax_error_response = self.uri_opener.send_mutant( self.mutant, cache=False, timeout=10 )
            syntax_error_response_time = syntax_error_response.get_wait_time()
            delta_time = abs( syntax_error_response_time - original_wait_time )
            self.debug("responses delta_time %f (%f) (%f)" % (delta_time, syntax_error_response_time, original_wait_time) )
            # if wait_time of syntax_error request had twice as much - may be sqlinj
            if delta_time > original_wait_time * 2:
                is_vuln = True
        except HTTPRequestException:
            self.debug("HTTPRequestException")
            is_vuln = True

        if is_vuln:
            response_ids = [syntax_error_response.id]
            
            desc = 'Suspicion for Blind SQL injection at: "%s", using'\
                   ' HTTP method %s. The injectable parameter may be: "%s"'
            desc = desc % (self.mutant.get_url(),
                           self.mutant.get_method(),
                           self.mutant.get_token_name())
            
            v = Vuln.from_mutant('Blind SQL injection vulnerability', desc,
                                 severity.MEDIUM, response_ids, 'blind_sqli',
                                 self.mutant)
            
            om.out.debug(v.get_desc())

            v['error_html'] = syntax_error_response.get_body()
            v['delta_time'] = delta_time
            return v

    def _get_random_letters(self, maxlen=25):
        letters_chars = bytearray( string.letters )
        random_letters = ''
        for _ in xrange( maxlen ):
            random_letters += chr( letters_chars.pop( int( random() * len(letters_chars) ) ) )
        return random_letters.replace("'",'').replace('"','').replace('\\','')