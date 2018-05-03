from urlparse import urlparse
from os.path import split
from fuzzywuzzy import fuzz

FUZZ_COMPARE_FACTOR = 80

class FuzzyBrowser(object):
    def __init__(self, fuzz_compare_factor):
        self.fuzz_compare_factor = fuzz_compare_factor
        self.known_parts = ['/']

    def _save_page(self, parts):
		for i in xrange( len(parts) ):
			if not parts[i] in self.known_parts:
				self.known_parts.append( parts[i] )
			 
    def add_page(self, uri):
        self._save_page( ['/'] + urlparse(uri).path.split('/')[1:] )

    def check_page(self, uri):
		parts = ['/'] + urlparse(uri).path.split('/')[1:]
		parts_ratios = [100]
		for level in xrange( 1, len(parts) ):
			part = parts[level]
			if not part:
				continue
			ratios = []
			for saw_part in self.known_parts:
				ratio = fuzz.ratio( part, saw_part ) + level*5
				ratios.append(ratio if ratio < 100 else 100)
			parts_ratios.append( max(ratios) )
		
		match = False
		#print parts
		#print parts_ratios
		for parts_ratio in parts_ratios:
			if self.fuzz_compare_factor >= parts_ratio:
				match = True
		return match

if __name__ == '__main__':
	from colorama import Fore
	browser = FuzzyBrowser(80)
	while True:
		try:
			line = raw_input()
		except:
			break
		
		if browser.check_page(line):
			browser.add_page(line)
			print Fore.GREEN + line + Fore.RESET
		else:
			print Fore.RED + line + Fore.RESET
		