"""
XmlMutant.py

2018 soier

"""
from w3af.core.data.fuzzer.mutants.postdata_mutant import PostDataMutant
from w3af.core.data.dc.xml_container import XMLContainer


class XMLMutant(PostDataMutant):
    """
    This class is an XML mutant.
    """
    @staticmethod
    def get_mutant_type():
        return 'XML data'

    def get_headers(self):
        # TODO: Not working?
        #headers = super(XmlRpcMutant, self).get_headers()
        headers = self.get_fuzzable_request().get_headers()
        headers['Content-Type'] = 'application/xml'
        return headers

    def found_at(self):
        """
        I had to implement this again here instead of just inheriting from
        PostDataMutant because of the duplicated parameter name support which
        I added to the framework.

        :return: A string representing WHAT was fuzzed.
        """
        fmt = '"%s", using HTTP method %s. The sent XML-RPC was: "%s".'
        return fmt % (self.get_url(), self.get_method(),
                      self.get_dc().get_short_printable_repr())

    @classmethod
    def create_mutants(cls, freq, mutant_str_list, fuzzable_param_list,
                       append, fuzzer_config, data_container=None):
        """
        This is a very important method which is called in order to create
        mutants. Usually called from fuzzer.py module.
        """
        if not isinstance(freq.get_raw_data(), XMLContainer):
            return []

        return cls._create_mutants_worker(freq, cls, mutant_str_list,
                                          fuzzable_param_list, append,
                                          fuzzer_config)