// Copyright (c) 2016-2023 The Hush developers
// Copyright (c) 2017 The Zen Core developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

#ifndef UTILTLS_H
#define UTILTLS_H

namespace hush {

#define CERT_VALIDITY_DAYS  (365 * 10)   // period of validity, in days, for a self-signed certificate

WOLFSSL_EVP_PKEY* GenerateEcKey(int nid = NID_X9_62_prime256v1);
WOLFSSL_X509* GenerateCertificate(WOLFSSL_EVP_PKEY *keypair);

}

#endif // UTILTLS_H
