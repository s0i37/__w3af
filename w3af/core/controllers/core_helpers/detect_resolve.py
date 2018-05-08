import dns.resolver

class Resolver:
	def __init__(self, zone):
		self._resolver = dns.resolver.Resolver()

		nameservers = []
		for ns in self._resolver.query(zone, "NS"):
			for ip in self._resolver.query( str(ns), "A" ):
				nameservers.append( str(ip) )
		self._resolver.nameservers = nameservers
		print str(self._resolver.nameservers)

	def query(self, fqdn, qtype='A'):
		#self._resolver.set_flags(0x20) # rd=0
		results = []
		try:
			for result in self._resolver.query(fqdn, qtype):
				results.append( str(result) )
		except:
			pass
		return results