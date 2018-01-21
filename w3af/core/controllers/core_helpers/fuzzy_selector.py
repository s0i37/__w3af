from urlparse import urlparse
from os.path import split
from fuzzywuzzy import fuzz

FUZZ_COMPARE_FACTOR = 80

class FuzzyBrowser(object):
    def __init__(self, fuzz_compare_factor):
        self.fuzz_compare_factor = fuzz_compare_factor
        self.tree = { '/': {} }

    def _save_page(self, parts):
		tree_ptr = self.tree
		for i in xrange( len(parts) ):
			 try:
				if parts[i] in tree_ptr:
					tree_ptr[ parts[i] ].update( { parts[i+1] : {} } )
				else:
					tree_ptr[ parts[i] ] = { parts[i+1] : {} }
				tree_ptr = tree_ptr[ parts[i] ]
			 except:
				 tree_ptr[ parts[i] ] = ''
				 
    def add_page(self, uri):
        self._save_page( ['/'] + urlparse(uri).path.split('/')[1:] )

    def check_page(self, uri):
		parts = ['/'] + urlparse(uri).path.split('/')[1:]
		parts_ratios = [100]
		tree_ptr = self.tree
		for level in xrange( 1, len(parts) ):
			part = parts[level]
			ratios = []
			if tree_ptr and tree_ptr.get( parts[level-1] ):
				for saw_part in tree_ptr[ parts[level-1] ]:
					ratio = fuzz.ratio( part, saw_part ) + len( tree_ptr[ parts[level-1] ] ) # width growth restriction
					ratios.append(ratio if ratio < 100 else 100)
				tree_ptr = tree_ptr.get( parts[level-1] )
			else:
				ratios.append(0)
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
		