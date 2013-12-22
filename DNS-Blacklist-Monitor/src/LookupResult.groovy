import groovy.time.TimeDuration

/**
 * <p>LookupResult class.</p>
 *
 * @author <a href="mailto:ronny@opennms.org">Ronny Trommer</a>
 * @version $Id: $
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
