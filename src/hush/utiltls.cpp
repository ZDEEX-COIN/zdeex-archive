// Copyright (c) 2017 The Zen Core developers
// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

#include <stdio.h>
#include <vector>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "../util.h"
#include "utiltls.h"

namespace hush {

// Generates EC keypair
//
WOLFSSL_EVP_PKEY* GenerateEcKey(int nid)
{
    WOLFSSL_EVP_PKEY *evpPrivKey = NULL;
    WOLFSSL_EC_KEY *privKey = wolfSSL_EC_KEY_new_by_curve_name(nid);
    if (privKey) {
        wolfSSL_EC_KEY_set_asn1_flag(privKey, OPENSSL_EC_NAMED_CURVE);
        if (wolfSSL_EC_KEY_generate_key(privKey)) {
            if ((evpPrivKey = wolfSSL_EVP_PKEY_new())) {
                if (!wolfSSL_EVP_PKEY_assign_EC_KEY(evpPrivKey, privKey)) {
                    wolfSSL_EVP_PKEY_free(evpPrivKey);
                    evpPrivKey = NULL;
                }
            }
        }

        if(!evpPrivKey) {
            wolfSSL_EC_KEY_free(privKey);
            evpPrivKey = NULL;
        }   
    }

    return evpPrivKey;
}

// Generates certificate for a specified public key using a corresponding private key (both of them should be specified in the 'keypair').
//
WOLFSSL_X509* GenerateCertificate(WOLFSSL_EVP_PKEY *keypair)
{
    if (!keypair) {
        LogPrintf("%s: Null keypair!\n", __func__);
        return NULL;
    } 

    WOLFSSL_X509 *cert = wolfSSL_X509_new();
    if (cert) {
        bool bCertSigned = false;
        long sn = 0;
        
        if (wolfSSL_RAND_bytes((unsigned char*)&sn, sizeof(sn)) &&wolfSSL_ASN1_INTEGER_set(wolfSSL_X509_get_serialNumber(cert), sn)) {
            wolfSSL_X509_gmtime_adj(wolfSSL_X509_get_notBefore(cert), 0);
            wolfSSL_X509_gmtime_adj(wolfSSL_X509_get_notAfter(cert), (60 * 60 * 24 * CERT_VALIDITY_DAYS));

            // setting a public key from the keypair
            if (wolfSSL_X509_set_pubkey(cert, keypair)) {
                // private key from keypair is used; signature will be set inside of the cert
                bCertSigned = wolfSSL_X509_sign(cert, keypair, wolfSSL_EVP_sha512());
            }
        } else {
            LogPrintf("%s: Unable to alloc rand bytes!\n", __func__);
        }

        if (!bCertSigned) {
            LogPrintf("%s: TLS cert not signed correctly!\n", __func__);
            wolfSSL_X509_free(cert);
            cert = NULL;
        }
    } else {
        LogPrintf("%s: Unable to create x509 cert!\n", __func__);
    }
    
    return cert;
}

}
