from urlparse import urlparse
from os.path import split
from fuzzywuzzy import fuzz

FUZZ_COMPARE_FACTOR = 80

class SmartBrowser(object):
    def __init__(self, fuzz_compare_factor):
        self.fuzz_compare_factor = fuzz_compare_factor
        self.saw_dirs = {}

    def _is_exist_dir(self, _dir):
        return True if self.saw_dirs.get(_dir) != None else False

    def _is_exist_file(self, _dir, _file):
        return True if _file in self.saw_dirs.get(_dir) else False
 
    def _add_new_dir(self, _dir):
        self.saw_dirs[ _dir ] = []

    def _add_new_file(self, _dir, _file):
        self.saw_dirs[ _dir ].append( _file )

    def _save_page(self, _dir, _file):
        if not self._is_exist_dir(_dir):
            self._add_new_dir(_dir)
        if not self._is_exist_file(_dir, _file):
            self._add_new_file( _dir, _file )

    def get_files_count(self, _dir):
        return len( self.saw_dirs[ _dir ] )

    def add_page(self, uri):
        path = urlparse(uri).path
        self._save_page( *split(path) )

    def check_page(self, uri):
        path = urlparse(uri).path
        _dir, _file = split(path)
        if self.get_files_count(_dir) > 1:
          for saw_file in self.saw_dirs[_dir][:-2]:
            ratio = fuzz.ratio( _file, saw_file )
            if ratio >= self.fuzz_compare_factor - self.get_files_count(_dir):
              return False
            else:
              return True
        else:
          return True

