#include <stdio.h>
#include <nss.h>
#include <nss/cert.h>
#include <nss/keyhi.h>
#include <nss/seccomon.h>
#include <nss/secder.h>
#include <nss/secerr.h>
#include <nss/secport.h>

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

static const char CERTIFICATE_HEADER[] = "-----BEGIN CERTIFICATE-----\r\n";
static const char CERTIFICATE_FOOTER[] = "-----END CERTIFICATE-----\r\n";

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
  if (strncmp(CERTIFICATE_FOOTER,
              data + length - strlen(CERTIFICATE_FOOTER) - 1,
              strlen(CERTIFICATE_FOOTER)) == 0) {
    data[length - strlen(CERTIFICATE_FOOTER) - 1] = 0;
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

void check_key_requirements(CERTCertificate *cert) {
  PRTime notAfter;
  SECStatus status = DER_DecodeTimeChoice(&notAfter, &cert->validity.notAfter);
  if (status != SECSuccess) {
    fprintf(stderr, "error decoding not after value");
    return;
  }

  PRTime cutoff;
  PRStatus rv = PR_ParseTimeString("31-DEC-2013 11:59 PM", PR_TRUE, &cutoff);
  if (rv != PR_SUCCESS) {
    fprintf(stderr, "Error parsing time string. This shouldn't happen.\n");
    exit(1);
  }

  SECOidTag algOIDTag = SECOID_FindOIDTag(&cert->signature.algorithm);
  if (algOIDTag != SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION &&
      algOIDTag != SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION &&
      algOIDTag != SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION &&
      algOIDTag != SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION) {
    fprintf(stderr, "BR Appendix A(3): digest algorithm must be SHA1, SHA-256, "
                    "SHA-384 or SHA-512 (is %s (%d))\n",
                    alg_tag_to_string(&algOIDTag), (int)algOIDTag);
  } else {
    fprintf(stdout, "BR Appendix A(3): digest algorithm must be SHA1, SHA-256, "
                    "SHA-384 or SHA-512 (is %s)\n",
                    alg_tag_to_string(&algOIDTag));
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

  if (strengthInBits < minimumStrength) {
    fprintf(stderr, "BR Appendix A(3): key modulus must be a minimum of %s "
                    "bits (is %u bits)\n", minimumStrengthStr,
                    strengthInBits);
  } else {
    fprintf(stdout, "BR Appendix A(3): key modulus must be a minimum of %s "
                    "bits (is %u bits)\n", minimumStrengthStr,
                    strengthInBits);
  }

  //key->u.rsa.modulus
  // TODO: need arbitrary length integer arithmetic library to do this right
  long pubExp = DER_GetInteger(&key->u.rsa.publicExponent);
  if (pubExp == -1) {
    fprintf(stderr, "Error decoding public exponent: %d\n", PORT_GetError());
  } else {
    if (pubExp < 3 || pubExp % 2 == 0) {
      fprintf(stderr, "BR Appendix A(4): public exponent must be an odd "
                      "number equal to 3 or more. It should be at least "
                      "65537 (it is %ld)\n", pubExp);
    } else {
      fprintf(stdout, "BR Appendix A(4): public exponent must be an odd "
                      "number equal to 3 or more. It should be at least "
                      "65537 (it is %ld)\n", pubExp);
    }
  }
}

void check_baseline_requirements(CERTCertificate *cert) {
  // BR #9.1.1 - issuer:commonName optional
  // BR #9.1.2 - issuer:domainComponent optional (if present, must include
  // all components if the issuing CA's registered domain name in ordered
  // sequence, with the most significant component (closest to the root of the
  // namespace) written last)
  // (TODO)

  // BR #9.1.3 - issuer:organizationName present
  char *org = CERT_GetOrgName(&cert->issuer);
  if (!org) {
    fprintf(stderr, "BR #9.1.3 (issuer:organizationName present) violated!\n");
  } else {
    fprintf(stdout, "BR #9.1.3 (issuer:organizationName present): %s\n", org);
    free(org);
  }

  // BR #9.1.4 - issuer:countryName present
  char *country = CERT_GetCountryName(&cert->issuer);
  if (!country) {
    fprintf(stderr, "BR #9.1.4 (issuer:countryName present) violated!\n");
  } else {
    fprintf(stdout, "BR #9.1.4 (issuer:countryName present): %s\n", country);
    free(country);
  }

  // BR #9.2.1 - extensions:subjectAltName contains at least one entry
  // TODO: there are more requirements
  SECItem subjectAltName;
  SECStatus status = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
                                            &subjectAltName);
  if (status != SECSuccess) {
    fprintf(stderr, "BR #9.2.1 (extensions:subjectAltName contains at least "
                    "one entry) violated!\n");
  } else {
    PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    CERTGeneralName *nameList = CERT_DecodeAltNameExtension(arena,
                                                            &subjectAltName);
    if (!nameList) {
      fprintf(stderr, "BR #9.2.1 (extensions:subjectAltName contains at least "
                      "one entry) violated!\n");
    } else {
      fprintf(stdout, "BR #9.2.1 (extensions:subjectAltName contains at least "
                      "one entry): true\n");
    }
    SECITEM_FreeItem(&subjectAltName, PR_FALSE);
    PORT_FreeArena(arena, PR_FALSE);
  }

  // BR #9.2.2 - subject:commonName deprecated (if present, must contain a
  // single IP address or FQDN that is one of the values contained in the
  // subjectAltName extension
  // (TODO)

  // BR #9.2.3 - subject:domainComponent optional (if present...)
  // (TODO)
  // BR #9.2.4 - subject:organizationName, etc... optional
  // (TODO)
  // BR #9.2.5 - subject:countryName conditionally optional
  // (TODO)
  // BR #9.2.6
  // BR #9.2.7
  // BR #9.2.8

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
