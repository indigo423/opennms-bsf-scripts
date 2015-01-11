#!/usr/bin/env groovy
@Grab(group='dnsjava', module='dnsjava', version='2.1.1')
import org.xbill.DNS.*
import groovy.time.TimeCategory
import groovy.time.TimeDuration

/**
 * Monitor to test if a zone in DNS is synchronized over several DNS name server.
 * The monitor request the SOA record for the given zone and compares the serial number.
 *
 * In the error reason the name server and the serial numbers are given.
 * The monitor can be compared with
 *
 * dig SOA <zone> @<nameserver>
 *
 * @author Ronny Trommer (ronny@opennms.org)
 * @since 1.0-SNAPSHOT
 */


/**
 * Initialize timeout for waiting on lookup, is initialized with 3000 milli seconds
 */
int TIMEOUT = 3000

/**
 * IP address to test
 */
def ipAddress = ip_addr

/**
 * Initialize zone for lookup as empty
 */
def zone = ''

/**
 * Initialize name servers with zone to test for sync test, space separated
 */
def nameservers = ''

/**
 * Assign servers as string array
 */
def servers = nameservers.tokenize()

/**
 * Initialize poller status with UNKNOWN --> Service down
 */
results.put('status', 'UNK')
results.put('reason', 'Initialized status as unknown.')

/**
 * Start time for total time measurement
 */
def timeStart = new Date()

/**
 * All zone serial numbers
 */
def serials = new HashSet()

/**
 * Zone serials ans name server for error reason
 */
def dnsResults = new HashMap()

// Iterate over all given name server
servers.each { server ->
	def resolver = new SimpleResolver(server)

	// Set default timeout in seconds
	resolver.timeout = TIMEOUT/1000

    def lookup = new Lookup(zone, Type.SOA)
	lookup.resolver = resolver

	// Disable DNS lookup cache
	lookup.cache = null

	// Iterate over all records from lookup
	lookup.run().each { result ->

		// Add serial number from name server
	    serials.add(result.serial)

		// Add serial number and name server for error reason
	    dnsResults.put(server, result.serial)
	}
}

// Stop total time measurement
def timeStop = new Date()

/**
 * Running the script
 */
// groovy poller is starting
bsf_monitor.log("DEBUG", "BSFMonitor [" + svc_name + "] start", null);

// Set timeout from service configuration
if (!map.get("timeout") == null) {
	TIMEOUT = map.get("timeout")
}

try {
	bsf_monitor.log("INFO", "service name: " + svc_name + " ipaddr: " + ipAddress + " node label: " + node_label + "[" + node_id + "]", null);

	// from map object
	bsf_monitor.log("INFO", "source script filename: " + map.get("file-name"), null)
	bsf_monitor.log("INFO", "parameter key=script_option from poller config: " + map.get("script_option"), null)
	bsf_monitor.log("INFO", "parameter key=nameservers from poller config: " + map.get("nameservers"), null)
} catch (e) {
	bsf_monitor.error("ERROR", "Error getting script filename. ${e}")
}

if (dnsResults.size() != servers.size()) {
	missing = servers - dnsResults.keySet()
	println("Some servers did not deliver SOA records: ${missing}")
	results.put('status', 'NOK')
	results.put('reason', "Server ${missing} didn't delivered SOA record.")
} else if (serials.size() > 1) {
	println("Found different serials: ${serials}")
	results.put('status', 'NOK')
	results.put('reason', "Server have different SOA serial number: ${dnsResults}")
} else {
	results.put('status', 'OK')
	results.put('reason', 'DNS serial numbers synchronized.')
}
// Calculate time duration
TimeDuration duration = TimeCategory.minus(timeStop, timeStart)
times.put('DnsSerialSyncTime', duration.toMilliseconds())
bsf_monitor.log("INFO", "BSFMonitor " + svc_name + " finished", null)
