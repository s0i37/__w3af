"""
xml_iter_setters.py

2018 xmltodict

"""

from lxml import etree

from w3af.core.data.dc.utils.token import DataToken


KEY_STRING = 'string'
KEY_OBJECT = 'object'
KEY_ARRAY = 'list'
KEY_NUMBER = 'number'
KEY_NULL = 'null'
KEY_BOOLEAN = 'boolean'

TO_WRAP_OBJS = (int, float, basestring)


def xml_iter_setters(arbitrary_python_obj):
    marbitrary_python_obj = to_mutable(arbitrary_python_obj)
    for k, v, s in _xml_iter_setters(marbitrary_python_obj):
        yield k, v, s


def to_mutable(arbitrary_python_obj):
    """
    :param arbitrary_python_obj: Any arbitrary python object (which comes form
                                 xml.loads). A combination of string, list,
                                 int, float, none and boolean.

    :return: We replace these [0] basic types with a wrapper object which allows
             me to provide a setter for those objects.

    [0] TO_WRAP_OBJS
    """
    if isinstance(arbitrary_python_obj, TO_WRAP_OBJS):
        return MutableWrapper(arbitrary_python_obj)

    elif isinstance(arbitrary_python_obj, MutableWrapper):
        value = to_mutable(arbitrary_python_obj.get_value())
        arbitrary_python_obj.set_value(value)
        return arbitrary_python_obj

    elif isinstance(arbitrary_python_obj, list):
        for idx, oapo in enumerate(arbitrary_python_obj):
            arbitrary_python_obj[idx] = to_mutable(oapo)

        return arbitrary_python_obj

    elif isinstance(arbitrary_python_obj, dict):
        for key, oapo in arbitrary_python_obj.iteritems():
            arbitrary_python_obj[key] = to_mutable(oapo)

        return arbitrary_python_obj


class MutableWrapper(object):
    """
    Wrapper around string, int and float which allows me to provide a setter
    around them. The
    """
    def __init__(self, wrapped_obj):
        self._wrapped_obj = wrapped_obj

    def get_value(self):
        return self._wrapped_obj

    def set_value(self, new_value):
        self._wrapped_obj = new_value

    def __getattr__(self, attr):
        # see if this object has attr
        # NOTE do not use hasattr, it goes into infinite recursion
        if attr in self.__dict__:
            # this object has it
            return getattr(self, attr)
        # proxy to the wrapped object
        return getattr(self._wrapped_obj, attr)


def _xml_iter_setters(marbitrary_python_obj, key_names=[]):
    if isinstance(marbitrary_python_obj, MutableWrapper):
        # We get here when we're iterating over a MutableWrapper, which is a
        # helper class to be able to "change the value of a string|float|int"

        value = marbitrary_python_obj.get_value()

        if isinstance(value, basestring):
            key_names = key_names[:]
            key_names.append(KEY_STRING)
            yield '-'.join(key_names), value, marbitrary_python_obj.set_value

        elif isinstance(value, (int, float)):
            key_names = key_names[:]
            key_names.append(KEY_NUMBER)
            yield '-'.join(key_names), value, marbitrary_python_obj.set_value

        elif isinstance(value, bool):
            key_names = key_names[:]
            key_names.append(KEY_BOOLEAN)
            yield '-'.join(key_names), value, marbitrary_python_obj.set_value

        elif value is None:
            key_names = key_names[:]
            key_names.append(KEY_NULL)
            yield '-'.join(key_names), value, marbitrary_python_obj.set_value

        elif isinstance(value, DataToken):
            for k, v, s in _xml_iter_setters(value, key_names=key_names):
                yield k, v, s
        else:
            for k, v, s in _xml_iter_setters(value, key_names=key_names):
                yield k, v, s

    elif isinstance(marbitrary_python_obj, list):
        for idx, list_item in enumerate(marbitrary_python_obj):
            array_key_names = key_names[:]
            array_key_names.append(KEY_ARRAY)
            array_key_names.append(str(idx))

            for k, v, s in _xml_iter_setters(list_item,
                                              key_names=array_key_names):
                yield k, v, s

    elif isinstance(marbitrary_python_obj, dict):
        for key, value in marbitrary_python_obj.iteritems():
            array_key_names = key_names[:]
            array_key_names.append(KEY_OBJECT)
            array_key_names.append(key)

            for k, v, s in _xml_iter_setters(value, key_names=array_key_names):
                yield k, v, s

class XML:
    def __init__(self, tag, parent=None):
        self.tag = tag
        self.text = ''
        self.attrs = {}
        self.children = []
        if parent:
            parent.children.append(self)

    def __setitem__(self, item, val):
        self.attrs[item] = val.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')

    def __call__(self, param):
        self.text = param.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')

    def __str__(self):
        out = "<%s" % self.tag
        for attr,val in self.attrs.items():
            out += ' %s="%s"' % (attr, val)
        if self.children:
            for children in self.children:
                self.text += str(children)
        out += '>%s</%s>' % (self.text, self.tag)
        return out


def xml_complex_str(arbitrary_xml, doctype):
    xml_dict = arbitrary_xml.get_value()

    def _xmliter(obj, elem):
        if isinstance(obj, dict):
            xmldict = obj
            for key,val in xmldict.items():
                if key.startswith('@'):
                    while True:
                        if isinstance( val, (MutableWrapper, DataToken) ):
                            val = val.get_value()
                        else:
                            elem[ key[1:] ] = val
                            break
                elif key.startswith('#'):
                    while True:
                        if isinstance( val, (MutableWrapper, DataToken) ):
                            val = val.get_value()
                        else:
                            elem(val)
                            break
                else:
                    _xmliter( val, elem=XML(key, parent=elem) )
        elif isinstance( obj, (MutableWrapper, DataToken) ):
            _xmliter( obj.get_value(), elem=elem )
        else:
            value = obj
            elem(value)
        return elem
    
    xml_str = doctype
    for root in xml_dict.keys():
        xml_str += str( _xmliter( xml_dict[root], XML(root) ) )
    return xml_str



''' only well-formed documents
def _old_xml_complex_str(arbitrary_xml, doctype):
    xml_dict = arbitrary_xml.get_value()

    def _xmliter(obj, elem):
        if isinstance(obj, dict):
            xmldict = obj
            for key,val in xmldict.items():
                if key.startswith('@'):
                    while True:
                        if isinstance( val, (MutableWrapper, DataToken) ):
                            val = val.get_value()
                        else:
                            elem.set( key[1:], val )
                            break
                elif key.startswith('#'):
                    while True:
                        if isinstance( val, (MutableWrapper, DataToken) ):
                            val = val.get_value()
                        else:
                            elem.text = val
                            break
                else:
                    _xmliter( val, elem=etree.SubElement(elem, key) )
        elif isinstance( obj, (MutableWrapper, DataToken) ):
            _xmliter( obj.get_value(), elem=elem )
        else:
            value = obj
            elem.text = value
        return elem
    
    xml_str = ''
    for root in xml_dict.keys():
        xml_str += etree.tostring( _xmliter( xml_dict[root], etree.Element(root) ), doctype=doctype ) #, xml_declaration=True, encoding="UTF-8" )
    return xml_str
'''