#!/usr/bin/env groovy

def zone = "gitslap.me"

def servers = [
        'ns.inwx.de',
        'ns2.inwx.de',
        'ns3.inwx.de',
	'8.8.8.7'
] as Set

///////////////////////////////////////////////////////////////////

@Grab(group='dnsjava', module='dnsjava', version='2.1.1')
import org.xbill.DNS.*

@Grab(group='com.google.guava', module='guava', version='18.0')
import com.google.common.collect.Sets

def serials = new HashSet()
def results = new HashMap()

servers.each { server ->
	def resolver = new SimpleResolver(server)
	resolver.timeout = 1

    def lookup = new Lookup(zone, Type.SOA)
	lookup.resolver = resolver
	lookup.cache = null

	lookup.run().each { result ->
	    serials.add(result.serial)
	    results.put(server, result.serial)
	}
}

if (results.size() != servers.size()) {
	missing = servers - results.keySet()
	println("Some servers did not deliver SOA records: ${missing}")
	System.exit(1)

} else if (serials.size > 1) {
	println("Found different serials: ${serials}")
	System.exit(2)
	
}
