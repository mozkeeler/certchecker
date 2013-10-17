// This is for (hopefully) not permanent copies of functions that NSS don't
// expose that are useful for verifying compliance with the Baseline
// Requirements.

#include <cert.h>
#include <certt.h>
#include <portreg.h>
#include <prenv.h>
#include <prnetdb.h>
#include <seccomon.h>
#include <secerr.h>
#include <sslerr.h>

#include "nss_private.h"

// From nss/lib/certdb/certdb.c
static SECStatus
cert_TestHostName(char * cn, const char * hn)
{
    static int useShellExp = -1;

    if (useShellExp < 0) {
        useShellExp = (NULL != PR_GetEnv("NSS_USE_SHEXP_IN_CERT_NAME"));
    }
    if (useShellExp) {
    	/* Backward compatible code, uses Shell Expressions (SHEXP). */
	int regvalid = PORT_RegExpValid(cn);
	if (regvalid != NON_SXP) {
	    SECStatus rv;
	    /* cn is a regular expression, try to match the shexp */
	    int match = PORT_RegExpCaseSearch(hn, cn);

	    if ( match == 0 ) {
		rv = SECSuccess;
	    } else {
		PORT_SetError(SSL_ERROR_BAD_CERT_DOMAIN);
		rv = SECFailure;
	    }
	    return rv;
	}
    } else {
	/* New approach conforms to RFC 2818. */
	char *wildcard    = PORT_Strchr(cn, '*');
	char *firstcndot  = PORT_Strchr(cn, '.');
	char *secondcndot = firstcndot ? PORT_Strchr(firstcndot+1, '.') : NULL;
	char *firsthndot  = PORT_Strchr(hn, '.');

	/* For a cn pattern to be considered valid, the wildcard character...
	 * - may occur only in a DNS name with at least 3 components, and
	 * - may occur only as last character in the first component, and
	 * - may be preceded by additional characters
	 */
	if (wildcard && secondcndot && secondcndot[1] && firsthndot 
	    && firstcndot  - wildcard  == 1
	    && secondcndot - firstcndot > 1
	    && PORT_Strrchr(cn, '*') == wildcard
	    && !PORT_Strncasecmp(cn, hn, wildcard - cn)
	    && !PORT_Strcasecmp(firstcndot, firsthndot)) {
	    /* valid wildcard pattern match */
	    return SECSuccess;
	}
    }
    /* String cn has no wildcard or shell expression.  
     * Compare entire string hn with cert name. 
     */
    if (PORT_Strcasecmp(hn, cn) == 0) {
	return SECSuccess;
    }

    PORT_SetError(SSL_ERROR_BAD_CERT_DOMAIN);
    return SECFailure;
}

SECStatus
cert_VerifySubjectAltName(const CERTCertificate *cert, const char *hn)
{
    PLArenaPool *     arena          = NULL;
    CERTGeneralName * nameList       = NULL;
    CERTGeneralName * current;
    char *            cn;
    int               cnBufLen;
    unsigned int      hnLen;
    int               DNSextCount    = 0;
    int               IPextCount     = 0;
    PRBool            isIPaddr       = PR_FALSE;
    SECStatus         rv             = SECFailure;
    SECItem           subAltName;
    PRNetAddr         netAddr;
    char              cnbuf[128];

    subAltName.data = NULL;
    hnLen    = strlen(hn);
    cn       = cnbuf;
    cnBufLen = sizeof cnbuf;

    rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME, 
				&subAltName);
    if (rv != SECSuccess) {
	goto fail;
    }
    isIPaddr = (PR_SUCCESS == PR_StringToNetAddr(hn, &netAddr));
    rv = SECFailure;
    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (!arena) 
	goto fail;

    nameList = current = CERT_DecodeAltNameExtension(arena, &subAltName);
    if (!current)
    	goto fail;

    do {
	switch (current->type) {
	case certDNSName:
	    if (!isIPaddr) {
		/* DNS name current->name.other.data is not null terminated.
		** so must copy it.  
		*/
		int cnLen = current->name.other.len;
		rv = CERT_RFC1485_EscapeAndQuote(cn, cnBufLen, 
					    (char *)current->name.other.data,
					    cnLen);
		if (rv != SECSuccess && PORT_GetError() == SEC_ERROR_OUTPUT_LEN) {
		    cnBufLen = cnLen * 3 + 3; /* big enough for worst case */
		    cn = (char *)PORT_ArenaAlloc(arena, cnBufLen);
		    if (!cn)
			goto fail;
		    rv = CERT_RFC1485_EscapeAndQuote(cn, cnBufLen, 
					    (char *)current->name.other.data,
					    cnLen);
		}
		if (rv == SECSuccess)
		    rv = cert_TestHostName(cn ,hn);
		if (rv == SECSuccess)
		    goto finish;
	    }
	    DNSextCount++;
	    break;
	case certIPAddress:
	    if (isIPaddr) {
		int match = 0;
		PRIPv6Addr v6Addr;
		if (current->name.other.len == 4 &&         /* IP v4 address */
		    netAddr.inet.family == PR_AF_INET) {
		    match = !memcmp(&netAddr.inet.ip, 
		                    current->name.other.data, 4);
		} else if (current->name.other.len == 16 && /* IP v6 address */
		    netAddr.ipv6.family == PR_AF_INET6) {
		    match = !memcmp(&netAddr.ipv6.ip,
		                     current->name.other.data, 16);
		} else if (current->name.other.len == 16 && /* IP v6 address */
		    netAddr.inet.family == PR_AF_INET) {
		    /* convert netAddr to ipv6, then compare. */
		    /* ipv4 must be in Network Byte Order on input. */
		    PR_ConvertIPv4AddrToIPv6(netAddr.inet.ip, &v6Addr);
		    match = !memcmp(&v6Addr, current->name.other.data, 16);
		} else if (current->name.other.len == 4 &&  /* IP v4 address */
		    netAddr.inet.family == PR_AF_INET6) {
		    /* convert netAddr to ipv6, then compare. */
		    PRUint32 ipv4 = (current->name.other.data[0] << 24) |
		                    (current->name.other.data[1] << 16) |
				    (current->name.other.data[2] <<  8) |
				     current->name.other.data[3];
		    /* ipv4 must be in Network Byte Order on input. */
		    PR_ConvertIPv4AddrToIPv6(PR_htonl(ipv4), &v6Addr);
		    match = !memcmp(&netAddr.ipv6.ip, &v6Addr, 16);
		} 
		if (match) {
		    rv = SECSuccess;
		    goto finish;
		}
	    }
	    IPextCount++;
	    break;
	default:
	    break;
	}
	current = CERT_GetNextGeneralName(current);
    } while (current != nameList);

fail:

    if (!(isIPaddr ? IPextCount : DNSextCount)) {
	/* no relevant value in the extension was found. */
	PORT_SetError(SEC_ERROR_EXTENSION_NOT_FOUND);
    } else {
	PORT_SetError(SSL_ERROR_BAD_CERT_DOMAIN);
    }
    rv = SECFailure;

finish:

    /* Don't free nameList, it's part of the arena. */
    if (arena) {
	PORT_FreeArena(arena, PR_FALSE);
    }

    if (subAltName.data) {
	SECITEM_FreeItem(&subAltName, PR_FALSE);
    }

    return rv;
}
