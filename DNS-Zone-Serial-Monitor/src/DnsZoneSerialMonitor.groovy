#!/usr/bin/env groovy

@Grab(group='dnsjava', module='dnsjava', version='2.1.1')
import org.xbill.DNS.*;

zone = "gitslap.me"

def dnsServer = [
        'ns.inwx.de',
        'ns2.inwx.de',
        'ns3.inwx.de'
]

def compareMap = new HashMap()
def dnsResults = new HashMap()

dnsServer.each{
    lookupServer = it;
    Resolver resolver = new SimpleResolver(lookupServer)
    Lookup lookup = new Lookup(zone,Type.SOA)
    lookup.setResolver(resolver)
    records = lookup.run()
    records.each {
        result = it
        compareMap.put(zone, result.getSerial())
        dnsResults.put(lookupServer, result.getSerial())
    }
}

if (compareMap.size() == 1) {
    println("Everything is awesome! " + compareMap.size())
    dnsResults.each {
        println("Detail for Zone: " + zone + " :: "+ it.getKey() + " :: " + it.getValue())
    }
} else {
    println("Fucked up! " + compareMap.size())
    dnsResults.each {
        println("Detail for Zone: " + zone + " :: "+ it.getKey() + " :: " + it.getValue())
    }
}





