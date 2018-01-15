"""
xml.py

2018 soier

"""
import xmltodict

from w3af.core.data.dc.generic.data_container import DataContainer
from w3af.core.data.dc.utils.filter_printable import filter_non_printable
from w3af.core.data.constants.encodings import UTF8
from w3af.core.data.dc.utils.xml_iter_setters import (xml_iter_setters,
                                                       xml_complex_str,
                                                       MutableWrapper)

ERR_MSG = 'Unsupported data "%s" for xml container.'


class XMLContainer(DataContainer):
    """
    This class represents a data container for xml.

    :author: soier (s0i37@ya.ru)
    """

    XML_CONTENT_TYPE = 'application/xml'

    def __init__(self, xml_post_data, encoding=UTF8):
        """
        :param xml_post_data: The XML data as string
        """
        DataContainer.__init__(self, encoding=encoding)

        if not isinstance(xml_post_data, basestring):
            raise TypeError(ERR_MSG % xml_post_data)

        if not XMLContainer.is_xml(xml_post_data):
            raise ValueError(ERR_MSG % xml_post_data[:50])

        self._xml = None
        self._raw_xml = None

        self.parse_xml(xml_post_data)

    def __reduce__(self):
        return self.__class__, (self._raw_xml,), {'token': self.token,
                                                   'encoding': self.encoding}

    def get_type(self):
        return 'XML'

    @staticmethod
    def is_xml_content_type(headers):
        content_type, _ = headers.iget('content-type', '')
        return 'xml' in content_type.lower()

    @staticmethod
    def is_xml(post_data):
        try:
            xmltodict.parse(post_data)
        except:
            return False
        else:
            return True

    @staticmethod
    def get_mutable_xml(xml_post_data):
        return MutableWrapper( xmltodict.parse(xml_post_data) )

    def parse_xml(self, xml_post_data):
        """
        Parses the xml post data and stores all the information required to
        fuzz it as attributes.

        :param xml_post_data: The XML as a string
        :raises: ValueError if the xml_post_data is not valid XML
        """
        try:
            self._xml = XMLContainer.get_mutable_xml(xml_post_data)
            self._raw_xml = xml_post_data
        except:
            raise ValueError(ERR_MSG % xml_post_data[:50])

    @classmethod
    def from_postdata(cls, headers, post_data):
        if not XMLContainer.is_xml_content_type(headers):
            raise ValueError('Missing xml content type.')

        return cls(post_data)

    def __str__(self):
        """
        :return: string representation by writing back to XML string
        """
        return xml_complex_str(self._xml)

    def __repr__(self):
        return '<XMLContainer (token: %s)>' % self.get_token()

    def token_filter(self, token_path, token_value):
        # Only return tokens for strings
        if isinstance(token_value, basestring):
            return True

        return False

    def iter_setters(self):
        """
        :yield: Tuples containing:
                    * The key name as a string
                    * The value as a string
                    * The setter to modify the value

                Only for the tokens which have a value with type "string",
                this is required, since we don't want to fuzz something which
                was a number with a string like "abc", it will simply break the
                server-side framework parsing and don't return anything useful.
        """
        for key, val, setter in xml_iter_setters(self._xml):
            path = (key,)

            if self.token_filter(path, val):
                yield key, val, path, setter

    def get_short_printable_repr(self):
        """
        :return: A string with a short printable representation of self
        """
        if self.get_token() is not None:
            # I want to show the token variable and value in the output
            token = self.get_token()
            dt_str = '<%(par)s>%(val)s</%(par)s>' % ( {"par": filter_non_printable(token.get_name()),
                                "val": filter_non_printable(token.get_value()) } )
            return '...%s...' % dt_str[:self.MAX_PRINTABLE-6]
        else:
            # I'll simply show the first N parameter and values until the
            # MAX_PRINTABLE is achieved
            return filter_non_printable(str(self))[:self.MAX_PRINTABLE]

    def get_headers(self):
        return [('Content-Type', self.XML_CONTENT_TYPE)]
