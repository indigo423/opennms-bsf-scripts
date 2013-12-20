/**
 * <p>SpamBlackListMonitor class.</p>
 *
 * @author <a href="mailto:ronny@opennms.org">Ronny Trommer</a>
 * @version $Id: $
 * @since 1.0-SNAPSHOT
 */


import groovy.time.TimeCategory
import groovy.time.TimeDuration

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

MAX_THREADS = 10

class LookupResult {
    String blProvider = null;
    boolean isBlacklisted = null;
    TimeDuration lookupTime = null;

    def String toString() {
        return "DNSRBL provider = [${blProvider}]; Is black listed = [${isBlacklisted}], Resolve time = [${lookupTime.toMilliseconds()} ms]"
    }
}

def myClosure = { blProvider, ipAddress -> blackListLookup(ipAddress, blProvider) }

//def ipAddress = '87.226.224.34'
def ipAddress = '31.15.64.120'

def Collection<LookupResult> blacklistResultList;

def blProviderList = [
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
]

def threadPool = Executors.newFixedThreadPool(MAX_THREADS)

def timeStart = new Date()

def buildQuery(String ipAddress, String blProvider) {
    def ipAddressOctets = ipAddress.split("\\.");
    def reverseIpString = ""

    for (octet in ipAddressOctets.reverse()) {
        reverseIpString += octet + "."
    }
    return reverseIpString + blProvider
}

def LookupResult blackListLookup(String ipAddress, String blProvider) {
    def query = buildQuery(ipAddress, blProvider)
    def startLookupTime = new Date()
    def LookupResult lookupResult = new LookupResult()

    try {
        lookupResult.blProvider = blProvider
        InetAddress.getByName(query)
        lookupResult.isBlacklisted = true;
    } catch (UnknownHostException e) {
        lookupResult.isBlacklisted = false;
    }

    def stopLookupTime = new Date()
    TimeDuration duration = TimeCategory.minus(stopLookupTime, startLookupTime)
    lookupResult.lookupTime = duration

    return lookupResult
}

def String buildMonitoringOutput(Collection blacklistResultList) {
    def output = ""

    for (blacklistResult in blacklistResultList) {
        if (blacklistResult.isBlacklisted) {
            if ("".equals(output)) {
                output += blacklistResult.blProvider
            } else {
                output = "${output}, ${blacklistResult.blProvider}"
            }
        }
    }

    if ("".equals(output)) {
        output
    }
    return output
}

try {
    List<Future> futures = blProviderList.collect { blProvider ->
        threadPool.submit({ ->
            myClosure blProvider, ipAddress
        } as Callable);
    }
    blacklistResultList = futures.collect { it.get() }
} finally {
    threadPool.shutdown()
    threadPool.awaitTermination(10, TimeUnit.SECONDS)
}

def timeStop = new Date()

TimeDuration duration = TimeCategory.minus(timeStop, timeStart)

println "${duration.toMilliseconds()}, " + buildMonitoringOutput(blacklistResultList)

