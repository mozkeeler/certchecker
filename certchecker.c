#include <stdio.h>
#include <nss.h>
#include <nss/cert.h>
#include <nss/keyhi.h>
#include <nss/seccomon.h>
#include <nss/secder.h>
#include <nss/secerr.h>
#include <nss/secport.h>
#include <prprf.h>

#include "nss_private.h"

char *read_file(const char *filename, size_t *length) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("fopen");
    return NULL;
  }
  int retval;
  retval = fseek(fp, 0L, SEEK_END);
  if (retval == -1) {
    perror("fseek");
    return NULL;
  }
  long size = ftell(fp);
  if (size == -1) {
    perror("ftell");
    return NULL;
  }
  fseek(fp, 0L, SEEK_SET);
  if (retval == -1) {
    perror("fseek");
    return NULL;
  }
  char *data = malloc(size + 1);
  if (!data) {
    perror("malloc");
    return NULL;
  }
  retval = fread(data, 1, size, fp);
  if (retval == -1 || retval != size) {
    perror("fread");
    return NULL;
  }

  data[size] = 0;
  *length = size + 1;
  return data;
}

static const char CERTIFICATE_HEADER[] = "-----BEGIN CERTIFICATE-----";
static const char CERTIFICATE_FOOTER[] = "-----END CERTIFICATE-----";

CERTCertificate *read_certificate_from_file(const char *filename) {
  size_t length = 0; // includes trailing \0
  char *data = read_file(filename, &length);
  if (!data) {
    return NULL;
  }
  char *ptr = data;
  if (strncmp(CERTIFICATE_HEADER, data, strlen(CERTIFICATE_HEADER)) == 0) {
    ptr += strlen(CERTIFICATE_HEADER);
  }
  while (ptr < data + length && (*ptr == '\r' || *ptr == '\n')) {
    ptr++;
  }
  char *endPtr = data + length - 2;
  while (endPtr > ptr && (*endPtr == '\r' || *endPtr == '\n')) {
    endPtr--;
  }
  endPtr -= strlen(CERTIFICATE_FOOTER) - 1;
  if (endPtr > ptr && strncmp(CERTIFICATE_FOOTER, endPtr,
                              strlen(CERTIFICATE_FOOTER)) == 0) {
    *endPtr = 0;
  }
  CERTCertificate *cert = CERT_ConvertAndDecodeCertificate(ptr);
  if (!cert) {
    fprintf(stderr, "could not decode %s: %d\n", filename, PORT_GetError());
    return NULL;
  }
  free(data);
  return cert;
}

const char *alg_tag_to_string(SECOidTag *tag) {
  switch (*tag) {
    case SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION:
      return "SHA1";
    case SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION:
      return "SHA256";
    case SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION:
      return "SHA384";
    case SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION:
      return "SHA512";
    default:
      return "unhandled OID tag";
  }
}

int certificate_has_policy(CERTCertificate *cert, const char *policy_string) {
  SECItem policyItem;
  SECStatus status = CERT_FindCertExtension(cert,
                                            SEC_OID_X509_CERTIFICATE_POLICIES,
                                            &policyItem);
  if (status != SECSuccess) {
    return 0;
  }

  CERTCertificatePolicies *policies;
  policies = CERT_DecodeCertificatePoliciesExtension(&policyItem);
  if (!policies) {
    fprintf(stderr, "error decoding certificate policies extension\n");
    PORT_Free(policyItem.data);
    return 0;
  }

  int retval = 0;
  CERTPolicyInfo **policyInfos = policies->policyInfos;
  while (*policyInfos != NULL) {
    char *oidString = CERT_GetOidString(&(*policyInfos)->policyID);
    if (strcmp(oidString, policy_string) == 0) {
      retval = 1;
    }
    PR_smprintf_free(oidString);
    policyInfos++;
  }

  CERT_DestroyCertificatePoliciesExtension(policies);
  PORT_Free(policyItem.data);
  return retval;
}

void check_key_requirements(CERTCertificate *cert) {
  PRTime notAfter;
  SECStatus status = DER_DecodeTimeChoice(&notAfter, &cert->validity.notAfter);
  if (status != SECSuccess) {
    fprintf(stdout, "error decoding not after value\n");
    return;
  }

  PRTime cutoff;
  PRStatus rv = PR_ParseTimeString("31-DEC-2013 11:59 PM", PR_TRUE, &cutoff);
  if (rv != PR_SUCCESS) {
    fprintf(stderr, "Error parsing time string. This shouldn't happen.\n");
    exit(1);
  }

  fprintf(stdout, "BR Appendix A(3): digest algorithm must be SHA1, SHA-256, "
                  "SHA-384 or SHA-512: ");
  SECOidTag algOIDTag = SECOID_FindOIDTag(&cert->signature.algorithm);
  if (algOIDTag != SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION &&
      algOIDTag != SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION &&
      algOIDTag != SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION &&
      algOIDTag != SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION) {
    fprintf(stdout, "FAIL: is %s (%d)\n", alg_tag_to_string(&algOIDTag),
            (int)algOIDTag);
  } else {
    fprintf(stdout, "PASS: is %s\n", alg_tag_to_string(&algOIDTag));
  }

  SECKEYPublicKey *key = CERT_ExtractPublicKey(cert);
  if (!key) {
    fprintf(stderr, "no public key in certificate?");
    return;
  }

  if (key->keyType != rsaKey) {
    fprintf(stderr, "Currently, only RSA keys are supported by this tool.\n");
    return;
  }

  unsigned strengthInBits = SECKEY_PublicKeyStrengthInBits(key);
  unsigned minimumStrength = 2048;
  const char *minimumStrengthStr = "2048";
  if (notAfter < cutoff) {
    minimumStrength = 1024;
    minimumStrengthStr = "1024";
  }

  fprintf(stdout, "BR Appendix A(3): key modulus must be a minimum of %s "
                  "bits: ", minimumStrengthStr);
  if (strengthInBits < minimumStrength) {
    fprintf(stdout, "FAIL: is %u\n", strengthInBits);
  } else {
    fprintf(stdout, "PASS: is %u\n", strengthInBits);
  }

  // TODO: need arbitrary length integer arithmetic library to do this right
  fprintf(stderr, "BR Appendix A(4): public exponent must be an odd "
                  "number equal to 3 or more. It should be at least "
                  "65537: ");
  long pubExp = DER_GetInteger(&key->u.rsa.publicExponent);
  if (pubExp == -1) {
    fprintf(stderr, "Error decoding public exponent: %d\n", PORT_GetError());
  } else {
    if (pubExp < 3 || pubExp % 2 == 0) {
      fprintf(stderr, "FAIL: is %ld\n", pubExp);
    } else if (pubExp < 65537) {
      fprintf(stderr, "WARN: is %ld\n", pubExp);
    } else {
      fprintf(stderr, "PASS: is %ld\n", pubExp);
    }
  }
}

void print_general_name(CERTGeneralName *name) {
  char *tmp = malloc(name->name.other.len + 1);
  memcpy(tmp, name->name.other.data, name->name.other.len);
  tmp[name->name.other.len] = 0;
  fprintf(stdout, "%s", tmp);
  free(tmp);
}

void hexdump(const unsigned char *data, unsigned length) {
  unsigned rows = length / 16;
  unsigned remainder = length % 16;
  unsigned i = 0;
  for (; i < rows; i++) {
    unsigned j = 0;
    for (; j < 8; j++) {
      fprintf(stdout, "%02hhx ", data[16*i + j]);
    }
    fprintf(stdout, " ");
    for (; j < 16; j++) {
      fprintf(stdout, "%02hhx ", data[16*i + j]);
    }
    fprintf(stdout, "\n");
  }
  unsigned j = 0;
  for (; j < 8 && j < remainder; j++) {
    fprintf(stdout, "%02hhx ", data[16*i + j]);
  }
  fprintf(stdout, " ");
  for (; j < 16 && j < remainder; j++) {
    fprintf(stdout, "%02hhx ", data[16*i + j]);
  }
  fprintf(stdout, "\n");
}

int check_subject_for(CERTCertificate *cert) {
  int count = 0;
  char *organizationName = CERT_GetOrgName(&cert->subject);
  if (organizationName) {
    count++;
    PORT_Free(organizationName);
  }
  // TODO: street address
  char *localityName = CERT_GetLocalityName(&cert->subject);
  if (localityName) {
    count++;
    PORT_Free(localityName);
  }
  char *stateOrProvinceName = CERT_GetStateName(&cert->subject);
  if (stateOrProvinceName) {
    count++;
    PORT_Free(stateOrProvinceName);
  }
  // TODO: postal code
  return count;
}

void check_baseline_requirements(CERTCertificate *cert) {
  // BR #9.1.1 - issuer:commonName optional
  // BR #9.1.2 - issuer:domainComponent optional (if present, must include
  // all components if the issuing CA's registered domain name in ordered
  // sequence, with the most significant component (closest to the root of the
  // namespace) written last)
  // (TODO)

  // BR #9.1.3 - issuer:organizationName present
  fprintf(stdout, "BR #9.1.3: issuer:organizationName present: ");
  char *org = CERT_GetOrgName(&cert->issuer);
  if (!org) {
    fprintf(stdout, "FAIL: not present\n");
  } else {
    fprintf(stdout, "PASS: present: %s\n", org);
    free(org);
  }

  // BR #9.1.4 - issuer:countryName present
  fprintf(stdout, "BR #9.1.4: issuer:countryName present: ");
  char *country = CERT_GetCountryName(&cert->issuer);
  if (!country) {
    fprintf(stdout, "FAIL: not present\n");
  } else {
    fprintf(stdout, "PASS: present: %s\n", country);
    free(country);
  }

  // BR #9.2.1 - extensions:subjectAltName contains at least one entry
  // TODO: there are more requirements
  fprintf(stdout, "BR #9.2.1: extensions:subjectAltName contains at least "
                  "one entry: ");
  SECItem subjectAltName;
  SECStatus status = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
                                            &subjectAltName);
  CERTGeneralName *nameList = NULL;
  if (status != SECSuccess) {
    fprintf(stdout, "FAIL\n");
  } else {
    PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    nameList = CERT_DecodeAltNameExtension(arena, &subjectAltName);
    if (!nameList) {
      fprintf(stdout, "FAIL\n");
    } else {
      fprintf(stdout, "PASS\n");
      fprintf(stdout, "BR #9.2.1: each extensions:subjectAltName entry "
                      "must be a DNS name or an IP address: ");
      int improperSubjectAltNameEntries = 0;
      CERTGeneralName *first = nameList;
      do {
        if (nameList->type != certDNSName && nameList->type != certIPAddress) {
          // see CERTGeneralNameType to figure out what type this is (TODO)
          fprintf(stdout, "FAIL: found type %d\n", nameList->type);
          improperSubjectAltNameEntries++;
        }
        nameList = CERT_GetNextGeneralName(nameList);
      } while (nameList != first);
      nameList = first;
      if (improperSubjectAltNameEntries == 0) {
        fprintf(stdout, "PASS\n");
      }
      do {
        if (nameList->type != certDNSName && nameList->type != certIPAddress) {
          fprintf(stdout, "extensions:subjectAltName: found ");
          print_general_name(nameList);
          fprintf(stdout, "\n");
        }
        nameList = CERT_GetNextGeneralName(nameList);
      } while (nameList != first);
      nameList = first;
    }
    SECITEM_FreeItem(&subjectAltName, PR_FALSE);
    PORT_FreeArena(arena, PR_FALSE);
  }

  // BR #9.2.2 - subject:commonName deprecated (if present, must contain a
  // single IP address or FQDN that is one of the values contained in the
  // subjectAltName extension
  fprintf(stdout, "BR #9.2.2: subject:commonName is deprecated: ");
  char *commonName = CERT_GetCommonName(&cert->subject);
  if (commonName) {
    fprintf(stdout, "WARN: common name present: %s\n", commonName);
    fprintf(stdout, "BR #9.2.2: subject:commonName if present, must match "
                    "one of the values in the subjectAltName extension: ");
    status = cert_VerifySubjectAltName(cert, commonName);
    if (status != SECSuccess) {
      fprintf(stdout, "FAIL\n");
    } else {
      fprintf(stdout, "PASS\n");
    }
    PORT_Free(commonName);
  } else {
    fprintf(stdout, "PASS\n");
  }

  // BR #9.2.3 - subject:domainComponent optional (if present...)
  // (TODO)
  // BR #9.2.4 - subject:organizationName, etc... optional
  // (TODO)
  // BR #9.2.5 - subject:countryName conditionally optional
  // (TODO)
  // BR #9.2.6
  // BR #9.2.7
  // BR #9.2.8

  // BR #9.3.1 - If the Certificate asserts the policy identifier of
  // 2.23.140.1.2.1, then it MUST NOT include organizationName,
  // streetAddress, localityName, stateOrProvinceName, or postalCode
  // in the Subject field.
  // If the Certificate asserts the policy identifier of 2.23.140.1.2.2,
  // then it MUST also include organizationName, localityName,
  // stateOrProvinceName (if applicable), and countryName in the Subject field.
  if (certificate_has_policy(cert, "OID.2.23.140.1.2.1")) {
    fprintf(stdout, "BR #9.3.1 - found policy 2.23.140.1.2.1: must not "
            "include organizationName, streetAddress, localityName, "
            "stateOrProvinceName, or postalCode in the Subject field: ");
    int fieldsPresent = check_subject_for(cert);
    if (fieldsPresent != 0) {
      fprintf(stdout, "FAIL\n");
    } else {
      fprintf(stdout, "PASS\n");
    }
  } else if (certificate_has_policy(cert, "OID.2.23.140.1.2.2")) {
    fprintf(stdout, "BR #9.3.1 - found policy 2.23.140.1.2.1: must "
            "include organizationName, streetAddress, localityName, "
            "stateOrProvinceName, and postalCode in the Subject field: ");
    int fieldsPresent = check_subject_for(cert);
    if (fieldsPresent != 3) { // TODO this isn't even right
      fprintf(stdout, "FAIL\n");
    } else {
      fprintf(stdout, "PASS\n");
    }
  } else {
    fprintf(stdout, "BR #9.3.1: not applicable (no policies found): PASS\n");
  }

  check_key_requirements(cert);
}

int main(int argc, const char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <certificate>\n", argv[0]);
    return 1;
  }

  SECStatus status;
  status = NSS_NoDB_Init(NULL);
  if (status != SECSuccess) {
    fprintf(stderr, "could not initialize NSS\n");
    return 1;
  }

  CERTCertificate *cert = read_certificate_from_file(argv[1]);
  if (!cert) {
    return 1;
  }
  check_baseline_requirements(cert);
  CERT_DestroyCertificate(cert);

  status = NSS_Shutdown();
  if (status != SECSuccess) {
    fprintf(stderr, "could not shutdown NSS\n");
    return 1;
  }
  return 0;
}
