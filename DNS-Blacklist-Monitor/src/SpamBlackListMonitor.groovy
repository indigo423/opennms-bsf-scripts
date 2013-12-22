#!/usr/bin/env groovy
import groovy.time.TimeCategory
import groovy.time.TimeDuration
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future

/**
 * Multi-threaded monitor to check if a specific IP address is registered
 * on a DNS Realtime Blacklist (DNSRBL) service. The monitor uses the
 * reverse IP DNS lookups against a set of DNSRBL provider. For DNS lookup
 * the InetAddress.getByName is used.
 *
 * For example:
 * ------------
 * Check if a mail server with the IP address 87.226.224.34 is registered
 * on bl.spamcop.net would be
 *
 *   host 34.224.226.87.bl.spamcop.net
 *   34.224.226.87.bl.spamcop.net has address 127.0.0.2
 *
 * If the reverse address has an A record the IP address for the mail server
 * is on the block list of the given DNSRBL server. If you don't have an
 * A record the server is not blocked.
 *
 * The monitor does not support IPv6.
 *
 *
 * The following variables are passed into the script from OpenNMS:
 *
 *   map         - a Map object that contains all the various parameters passed
 *                 to the monitor from the service definition in the
 *                 poller-configuration.xml file
 *   ip_addr     - the IP address that is currently being polled.
 *   node_id     - the Node ID of the node the ip_addr belongs to
 *                 node_label - this nodes label
 *   node_label -  this nodes label
 *   svc_name    - the name of the service that is being polled
 *   bsf_monitor - the instance of the BSFMonitor object calling the script,
 *                 useful primarily for purposes of logging via its
 *                 log(String sev, String fmt, Object... args) method.
 *   results     - a hash map (string, string) that the script may use to pass its
 *                 results back to the BSFMonitor - the status indication should be
 *                 set into the entry with key "status", and for status indications
 *                 other than "OK," a reason code should be set into the entry with
 *                 key "reason"
 *   times       - an ordered hash map (string, number) that the script may use to
 *                 pass one or more response times back to the BSFMonitor
 *
 * @author Ronny Trommer (ronny@opennms.org)
 * @since 1.0-SNAPSHOT
 */

/**
 * Class with a lookup result. It represents a result from DNSRBL lookup.
 */
class LookupResult {

    /**
     * Name of the DNS real time blacklist provider
     */
    String blProvider = null;

    /**
     * Flag if the blacklist provider has the IP address on his block list
     */
    boolean isBlacklisted;

    /**
     * The response time for the DNS lookup
     */
    TimeDuration lookupTime = null

    /**
     * A clean output of the lookup result
     *
     * @return attributes as {@link java.lang.String}
     */
    @Override
    def String toString() {
        return "DNSRBL provider = [${blProvider}]; Is black listed = [${isBlacklisted}], Resolve time = [${lookupTime.toMilliseconds()} ms]"
    }
}
/**
 * Initialize logging framework
 */
Logger log = LoggerFactory.getLogger("POLLER");

/**
 * Amount of Threads for parallel the DNS lookups
 */
MAX_THREADS = 10

/**
 * Closure for parallel blacklist lookups
 */
def myClosure = { blProvider, ipAddress -> blackListLookup(ipAddress, blProvider) }

/**
 * IP address to test
 */
def ipAddress = ip_addr

/**
 * Collection with DNSRBL lookup results
 */
def Collection<LookupResult> blacklistResultList = null;

/**
 * Thread pool for DNS lookups
 */
def threadPool = Executors.newFixedThreadPool(MAX_THREADS)

/**
 * Start time for total time measurement
 */
def timeStart = new Date()

/**
 * List with all DNSRBL provider
 */
def dnsRblProviderList = [
        'b.barracudacentral.org',
        'bl.emailbasura.org',
        'bl.spamcannibal.org',
        'bl.spamcop.net',
        'blackholes.five-ten-sg.com',
        'blacklist.woody.ch',
        'bogons.cymru.com',
        'cbl.abuseat.org cdl.anti-spam.org.cn',
        'combined.abuse.ch combined.rbl.msrbl.net',
        'db.wpbl.info',
        'dnsbl-1.uceprotect.net',
        'dnsbl-2.uceprotect.net',
        'dnsbl-3.uceprotect.net',
        'dnsbl.ahbl.org',
        'dnsbl.cyberlogic.net',
        'dnsbl.inps.de',
        'dnsbl.sorbs.net drone.abuse.ch',
        'drone.abuse.ch',
        'duinv.aupads.org',
        'dul.dnsbl.sorbs.net dul.ru',
        'dyna.spamrats.com dynip.rothen.com',
        'http.dnsbl.sorbs.net',
        'images.rbl.msrbl.net',
        'ips.backscatterer.org ix.dnsbl.manitu.net',
        'korea.services.net',
        'misc.dnsbl.sorbs.net',
        'noptr.spamrats.com',
        'ohps.dnsbl.net.au omrs.dnsbl.net.au orvedb.aupads.org',
        'osps.dnsbl.net.au osrs.dnsbl.net.au owfs.dnsbl.net.au',
        'owps.dnsbl.net.au pbl.spamhaus.org',
        'phishing.rbl.msrbl.net',
        'psbl.surriel.com',
        'rbl.interserver.net rbl.megarbl.net',
        'rdts.dnsbl.net.au relays.bl.gweep.ca',
        'ricn.dnsbl.net.au',
        'rmst.dnsbl.net.au sbl.spamhaus.org',
        'short.rbl.jp',
        'smtp.dnsbl.sorbs.net',
        'socks.dnsbl.sorbs.net spam.abuse.ch',
        'spam.dnsbl.sorbs.net',
        'spam.rbl.msrbl.net',
        'spam.spamrats.com',
        'spamlist.or.kr',
        'spamrbl.imp.ch',
        't3direct.dnsbl.net.au',
        'tor.ahbl.org',
        'tor.dnsbl.sectoor.de',
        'torserver.tor.dnsbl.sectoor.de',
        'ubl.lashback.com',
        'ubl.unsubscore.com',
        'virbl.bit.nl',
        'virus.rbl.jp',
        'virus.rbl.msrbl.net web.dnsbl.sorbs.net',
        'wormrbl.imp.ch',
        'xbl.spamhaus.org',
        'zen.spamhaus.org',
        'zombie.dnsbl.sorbs.net'
/**
 * Commented very slow DNSRBL provider, cause resolve time is up to 35 seconds
 *      'relays.bl.kundenserver.de',
 *      'probes.dnsbl.net.au proxy.bl.gweep.ca proxy.block.transip.nl',
 *      'relays.nether.net residential.block.transip.nl'
 */
]

/**
 * Create DNS hostname to request A record. The IP address is reversed
 * and attached with the DNSRBL provider
 *
 * @param ipAddress IPv4 Address as {@link java.lang.String}
 * @param blProvider DNSRBL provider DNS domain as {@link java.lang.String}
 * @return reverse IP address with DNSRBL domain name as {@link java.lang.String}
 */
def private buildQuery(String ipAddress, String blProvider) {
    // Split IPv4 address in octets
    def ipAddressOctets = ipAddress.split("\\.");
    def reverseIpString = ""

    // Reverse IPv4 octets and append "."
    for (octet in ipAddressOctets.reverse()) {
        reverseIpString += octet + "."
    }

    // Return reversed IPv4 address with DNSRBL provider domain name
    return reverseIpString + blProvider
}

/**
 * Request DNS A record for given IPv4 address for a specific DNSRBL provider
 *
 * @param ipAddress IPv4 address as {@link java.lang.String}
 * @param blProvider Domain name of the DNSRBL provider as {@link java.lang.String}
 * @return lookup result as {@link LookupResult}
 */
def private LookupResult blackListLookup(String ipAddress, String blProvider) {
    // Build the host name for the DNS A record request
    def query = buildQuery(ipAddress, blProvider)

    // Start time measurement for specific DNS A record lookup
    def startLookupTime = new Date()

    // Initialize empty lookup result
    def LookupResult lookupResult = new LookupResult()

    // Try DNS lookup and filling up lookup result
    try {
        lookupResult.blProvider = blProvider

        // DNS A record request
        InetAddress.getByName(query)

        // DNS A record successful, IP address is registered on the DNSRBL provider
        lookupResult.isBlacklisted = true;
    } catch (UnknownHostException e) {

        // No A record found, IP address is not registered on the DNSRBL provider
        lookupResult.isBlacklisted = false;
    }

    // Stop time measurement for specific DNS A record lookup
    def stopLookupTime = new Date()

    // Calculate time difference
    TimeDuration duration = TimeCategory.minus(stopLookupTime, startLookupTime)

    // Fill time measurement in lookup result
    lookupResult.lookupTime = duration

    return lookupResult
}

/**
 * Create output for the monitoring system
 *
 * @param blacklistResultList
 *      with all DNS lookup results for all DNSRBL provider as {@link java.util.Collection}
 * @return Output for monitoring system as {@link java.lang.String}
 */
def private String buildMonitoringOutput(Collection blacklistResultList) {
    def output = ""

    // Iterate on all DNS lookup results
    for (blacklistResult in blacklistResultList) {
        if (blacklistResult.isBlacklisted) {
            // IP address is registered on a black list
            if ("".equals(output)) {
                // first entry
                output += "${blacklistResult.blProvider}"
            } else {
                // 2nd + entry
                output = "${output}, ${blacklistResult.blProvider}"
            }
        }
    }

    if ("".equals(output)) {
        // The IP address is not registered on any of the DNSRBL provider
        results.put("status", "OK")
    } else {
        // At least one DNSRBL provider has the IPv4 address registered and blocks the IP
        results.put("status", "NOK")
        results.put("reason", "IP address black listed on: " + output)

    }

    return output
}

/**
 * Running the script
 */
// groovy poller is starting
log.info('bsf %s start', svc_name);

try {
    log.info("service name: %s ipaddr: %s node id: %s nodelabel: %s", svc_name, ip_addr, node_id, node_label);
    // from map object
    log.info("source script filename: %s", map.get("file-name"));
    log.info("parameter key=script_option from poller config: %s", map.get("script_option"));
} catch (e) {
}

try {
    // Try to make lookups with parallel threads
    List<Future> futures = dnsRblProviderList.collect { blProvider ->
        threadPool.submit({ ->
            myClosure blProvider, ipAddress
        } as Callable);
    }

    // Get all results from threads
    blacklistResultList = futures.collect { it.get() } as Collection<LookupResult>
} finally {
    threadPool.shutdown()
}

// Stop total time measurement
def timeStop = new Date()

// Evaluate output and build result map
buildMonitoringOutput(blacklistResultList)

// Calculate time duration
TimeDuration duration = TimeCategory.minus(timeStop, timeStart)
times.put("DnsRblTotalTime", duration.toMilliseconds())
log.info('bsf %s finished', svc_name);
