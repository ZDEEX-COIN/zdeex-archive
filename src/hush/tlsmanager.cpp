// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/dh.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include "tlsmanager.h"
#include "utiltls.h"

using namespace std;
// store our preferred cipherlist so we can use it for debug/etc later on
std::string TLS_CIPHERLIST;

namespace hush
{
    static WOLFSSL_EVP_PKEY *mykey;
    static WOLFSSL_X509 *mycert;

// this is the 'dh crypto environment' to be shared between two peers and it is meant to be public, therefore
// it is OK to hard code it (or as an alternative to read it from a file)
// ----
// generated via: openssl dhparam -C  2048
static WOLFSSL_DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xFF, 0x4A, 0xA8, 0x6C, 0x68, 0xD4, 0x4C, 0x41, 0x73, 0x8D,
        0xD8, 0x14, 0x57, 0xF9, 0x1C, 0x35, 0x72, 0x5F, 0xCD, 0x24,
        0xCB, 0xD1, 0x77, 0x30, 0xC2, 0x9A, 0x69, 0x01, 0xCF, 0x01,
        0xDE, 0xD4, 0x67, 0xD4, 0xEE, 0x9A, 0x03, 0x1C, 0x27, 0x42,
        0x06, 0x3D, 0x1D, 0x91, 0x27, 0xCF, 0x1C, 0x17, 0xB3, 0xDC,
        0x9F, 0x6F, 0x12, 0xC8, 0x03, 0x5C, 0x01, 0xF3, 0x27, 0x7F,
        0x34, 0x58, 0xAE, 0xB9, 0xA7, 0xA9, 0xCE, 0x5E, 0x25, 0x7D,
        0x46, 0x84, 0xDD, 0xEE, 0x55, 0xFB, 0xEA, 0x1C, 0xCD, 0x9B,
        0x96, 0xC4, 0x22, 0x8C, 0x33, 0x8B, 0xC7, 0xE6, 0xCC, 0x4C,
        0x77, 0x1B, 0x7A, 0x46, 0xDE, 0x33, 0xAD, 0xBB, 0xFD, 0x2D,
        0xAD, 0x26, 0xE1, 0x27, 0x48, 0x94, 0xA3, 0x59, 0xC5, 0x10,
        0x5A, 0x86, 0x71, 0x8D, 0xAA, 0x15, 0x8B, 0xB2, 0xCB, 0x70,
        0xBE, 0x1F, 0x17, 0xBD, 0xEB, 0x51, 0xB1, 0x76, 0x0E, 0x24,
        0x43, 0xAA, 0x06, 0xC0, 0x97, 0x01, 0x25, 0x52, 0x30, 0x7A,
        0x56, 0x92, 0x3D, 0x8A, 0x3A, 0xBC, 0xFA, 0x98, 0x51, 0x04,
        0x1D, 0x9B, 0x05, 0xB8, 0x84, 0x8C, 0x2F, 0x7A, 0x94, 0x1E,
        0xAA, 0x51, 0xF2, 0x5D, 0x48, 0x50, 0x58, 0x8D, 0x7E, 0xBA,
        0xD3, 0xCC, 0xF2, 0x92, 0x28, 0xB1, 0x1C, 0x4B, 0x50, 0x10,
        0xFA, 0x7E, 0xDF, 0x8D, 0x23, 0x1C, 0x8C, 0x65, 0xE3, 0x86,
        0x16, 0x67, 0x88, 0x9E, 0xFC, 0x8B, 0xC8, 0x55, 0x38, 0x6E,
        0x79, 0x06, 0x6A, 0x6D, 0x72, 0x75, 0xA6, 0xAC, 0x77, 0x98,
        0xDD, 0xB2, 0x0B, 0xAA, 0x48, 0x54, 0xA9, 0x07, 0x7E, 0x8C,
        0x4C, 0x39, 0x08, 0x26, 0x6D, 0x53, 0xC2, 0xDF, 0xE2, 0xF0,
        0xD6, 0x8A, 0x4F, 0xB5, 0x7A, 0x32, 0xEE, 0x93, 0x0E, 0x2A,
        0x81, 0x2F, 0x3B, 0x1E, 0xE6, 0x38, 0xF8, 0x3C, 0xF5, 0x84,
        0xB4, 0xFB, 0x92, 0x12, 0x28, 0xA3
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    
    WOLFSSL_DH *dh = wolfSSL_DH_new();
    
    if (dh == NULL) {
        return NULL;
    }

    if (wc_DhSetKey((DhKey*)dh->internal, dhp_2048, sizeof(dhp_2048), dhg_2048, sizeof(dhg_2048)) != 0) {
        wolfSSL_DH_free(dh);
        return NULL;
    }

    return dh;
}

DH *tmp_dh_callback(WOLFSSL *ssl, int is_export, int keylength) {
    LogPrint("tls", "TLS: %s: %s():%d - Using Diffie-Hellman param for PFS: is_export=%d, keylength=%d\n", __FILE__, __func__, __LINE__, is_export, keylength);

    return get_dh2048();
}

int TLSManager::waitFor(SSLConnectionRoutine eRoutine, SOCKET hSocket, WOLFSSL* ssl, int timeoutSec, unsigned long& err_code) {
    int retOp = 0;
    err_code  = 0;
    char err_buffer[1024];
    std::string disconnectedPeer("no info");

    while (true)
    {
        // clear the current thread's error queue
        wolfSSL_ERR_clear_error();

        switch (eRoutine) {
            case SSL_CONNECT:
            {
                retOp = wolfSSL_connect(ssl);
                if (retOp == 0) {
                    err_code = wolfSSL_ERR_get_error();
                    const char* error_str = wolfSSL_ERR_error_string(err_code, err_buffer);
                    LogPrint("tls", "TLS: WARNING: %s: %s():%d - SSL_CONNECT err: %s\n",
                        __FILE__, __func__, __LINE__, err_buffer);
                    return -1;
                }
            }
            break;
            
            case SSL_ACCEPT:
            {
                retOp = wolfSSL_accept(ssl);
                if (retOp == 0) {
                    err_code = wolfSSL_ERR_get_error();
                    const char* error_str = wolfSSL_ERR_error_string(err_code, err_buffer);
                    LogPrint("tls", "TLS: WARNING: %s: %s():%d - SSL_ACCEPT err: %s\n",
                        __FILE__, __func__, __LINE__, err_buffer);
                    return -1;
                }
            }
            break;
            
            case SSL_SHUTDOWN:
            {
                if (hSocket != INVALID_SOCKET) {
                    disconnectedPeer = "no info";
                    struct sockaddr_in addr;
                    socklen_t serv_len = sizeof(addr);
                    int ret = getpeername(hSocket, (struct sockaddr *)&addr, &serv_len);
                    if (ret == 0) {
                        disconnectedPeer = std::string(inet_ntoa(addr.sin_addr)) + ":" + std::to_string(ntohs(addr.sin_port));
                    }
                    LogPrint("tls", "TLS: shutting down fd=%d, peer=%s\n", hSocket, disconnectedPeer);
                }
                retOp = wolfSSL_shutdown(ssl);
            }
            break;
            
            default:
                return -1;
        }

        if (eRoutine == SSL_SHUTDOWN) {
            if (retOp == 0) {
                LogPrint("tls", "TLS: WARNING: %s: %s():%d - SSL_SHUTDOWN: The close_notify was sent but the peer did not send it back yet. Whatevz\n",
                        __FILE__, __func__, __LINE__);
                // do not call SSL_get_error() because it may misleadingly indicate an error even though no error occurred.
                break;
            } else if (retOp == 1) {
                LogPrint("tls", "TLS: %s: %s():%d - SSL_SHUTDOWN completed from peer %s\n", __FILE__, __func__, __LINE__, disconnectedPeer.c_str());
                break;
            } else {
                LogPrint("tls", "TLS: %s: %s():%d - SSL_SHUTDOWN failed to %s with ret=%d\n", __FILE__, __func__, __LINE__, disconnectedPeer.c_str(), retOp);
            }
        } else {
            if (retOp == 1) {
                std::string goodPeer = "";
                struct sockaddr_in addr;
                socklen_t serv_len = sizeof(addr);
                int ret = getpeername(hSocket, (struct sockaddr *)&addr, &serv_len);
                if (ret == 0) {
                    goodPeer = std::string(inet_ntoa(addr.sin_addr)) + ":" + std::to_string(ntohs(addr.sin_port));
                }
                LogPrint("tls", "TLS: %s: %s():%d - %s completed to %s\n", __FILE__, __func__, __LINE__,
                    eRoutine == SSL_CONNECT ? "SSL_CONNECT" : "SSL_ACCEPT", goodPeer);
                break;
            }
        }

        int sslErr = wolfSSL_get_error(ssl, retOp);

        if (sslErr != WOLFSSL_ERROR_WANT_READ && sslErr != WOLFSSL_ERROR_WANT_WRITE) {
            err_code = wolfSSL_ERR_get_error();
            const char* error_str = NULL;
            // calling this with err_code=0 generates more warnings, lulz
            if(err_code) {
                error_str = wolfSSL_ERR_error_string(err_code, err_buffer);
            }

            LogPrint("tls", "TLS: WARNING: %s: %s():%d - routine(%d), sslErr[0x%x], retOp[%d], errno[0x%x], lib[0x%x], func[0x%x], reas[0x%x]-> err: %s\n",
                __FILE__, __func__, __LINE__,
                eRoutine, sslErr, retOp, errno, wolfSSL_ERR_GET_LIB(err_code), ERR_GET_FUNC(err_code), wolfSSL_ERR_GET_REASON(err_code), error_str);
            retOp = -1;
            break;
        }

        fd_set socketSet;
        FD_ZERO(&socketSet);
        FD_SET(hSocket, &socketSet);

        struct timeval timeout = {timeoutSec, 0};

        if (sslErr == WOLFSSL_ERROR_WANT_READ) {
            int result = select(hSocket + 1, &socketSet, NULL, NULL, &timeout);
            if (result == 0) {
                LogPrint("tls", "TLS: ERROR: %s: %s():%d - WANT_READ timeout on %s\n", __FILE__, __func__, __LINE__,
                    (eRoutine == SSL_CONNECT ? "SSL_CONNECT" : 
                        (eRoutine == SSL_ACCEPT ? "SSL_ACCEPT" : "SSL_SHUTDOWN" )));
                err_code = SELECT_TIMEDOUT;
                retOp = -1;
                break;
            } else if (result == -1) {
                LogPrint("tls", "TLS: ERROR: %s: %s: WANT_READ ssl_err_code: 0x%x; errno: %s\n",
                    __FILE__, __func__, sslErr, strerror(errno));
                retOp = -1;
                break;
            }
        } else {
            int result = select(hSocket + 1, NULL, &socketSet, NULL, &timeout);
            if (result == 0) {
                LogPrint("tls", "TLS: ERROR: %s: %s():%d - WANT_WRITE timeout on %s\n", __FILE__, __func__, __LINE__,
                    (eRoutine == SSL_CONNECT ? "SSL_CONNECT" : 
                        (eRoutine == SSL_ACCEPT ? "SSL_ACCEPT" : "SSL_SHUTDOWN" )));
                err_code = SELECT_TIMEDOUT;
                retOp = -1;
                break;
            } else if (result == -1) {
                LogPrint("tls", "TLS: ERROR: %s: %s: WANT_WRITE ssl_err_code: 0x%x; errno: %s\n",
                    __FILE__, __func__, sslErr, strerror(errno));
                retOp = -1;
                break;
            }
        }
    }

    return retOp;
}

/**
 * @brief establish TLS connection to an address
 * 
 * @param hSocket socket
 * @param addrConnect the outgoing address
 * @param tls_ctx_client TLS Client context
 * @return WOLFSSL* returns a ssl* if successful, otherwise returns NULL.
 */
WOLFSSL* TLSManager::connect(SOCKET hSocket, const CAddress& addrConnect, unsigned long& err_code)
{
    LogPrint("tls", "TLS: establishing connection (tid = %X), (peerid = %s)\n", pthread_self(), addrConnect.ToString());

    err_code = 0;
    char err_buffer[1024];
    WOLFSSL* ssl = NULL;
    bool bConnectedTLS = false;

    if ((ssl = wolfSSL_new(tls_ctx_client))) {
        if (wolfSSL_set_fd(ssl, hSocket)) {
            int ret = TLSManager::waitFor(SSL_CONNECT, hSocket, ssl, (DEFAULT_CONNECT_TIMEOUT / 1000), err_code);
            if (ret == 1) {
                bConnectedTLS = true;
            } else {
                err_code = wolfSSL_ERR_get_error();
                LogPrint("tls", "%s: timed out waiting for %s\n", __func__, addrConnect.ToString());
            }
        } else {
            LogPrint("tls", "TLS: %s: failed to set file descriptor for socket!\n", __func__, addrConnect.ToString());
        }
    } else {
        err_code = wolfSSL_ERR_get_error();
        const char* error_str = wolfSSL_ERR_error_string(err_code, err_buffer);
        LogPrint("tls", "TLS: %s: %s():%d - SSL_new failed err: %s\n", __FILE__, __func__, __LINE__, err_buffer);
    }

    if (bConnectedTLS) {
        LogPrintf("TLS: connection to %s has been established (tlsv = %s 0x%04x / ssl = %s 0x%x ). Using cipher: %s\n",
            addrConnect.ToString(), wolfSSL_get_version(ssl), wolfSSL_version(ssl), wolfSSL_OpenSSL_version(), wolfSSL_lib_version_hex(), wolfSSL_get_cipher_name(ssl));
    } else {
        if(err_code) {
            LogPrintf("TLS: %s: %s():%d - TLS connection to %s failed with err_code=0x%X\n", __FILE__, __func__, __LINE__, addrConnect.ToString(), err_code);
        } else {
            LogPrintf("TLS: %s: %s():%d - TLS connection to %s timed out\n", __FILE__, __func__, __LINE__, addrConnect.ToString());
        }

        if (ssl) {
            wolfSSL_free(ssl);
            ssl = NULL;
        }
    }

    return ssl;
}
/**
 * @brief Initialize TLS Context
 * 
 * @param ctxType context type
 * @param privateKeyFile private key file path
 * @param certificateFile certificate key file path
 * @param trustedDirs trusted directories
 * @return WOLSSL_CTX* returns the context.
 */
WOLFSSL_CTX* TLSManager::initCtx(TLSContextType ctxType)
{
    LogPrintf("TLS: %s: %s():%d - Initializing %s context\n", 
         __FILE__, __func__, __LINE__, ctxType == SERVER_CONTEXT ? "server" : "client");

    if (!mykey || !mycert) {
        return NULL;   
    }
    
    bool bInitialized   = false;
    WOLFSSL_CTX* tlsCtx = NULL;

    byte *pem;
    int plen = 0;

    if ((tlsCtx = wolfSSL_CTX_new(ctxType == SERVER_CONTEXT ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method()))) {
        wolfSSL_CTX_set_mode(tlsCtx, SSL_MODE_AUTO_RETRY);

        // Disable TLS < 1.3, just in case
        int ret = wolfSSL_CTX_set_min_proto_version(tlsCtx, TLS1_3_VERSION);
        if (ret == 0) {
            LogPrintf("TLS: WARNING: %s: %s():%d - failed to set min TLS version\n", __FILE__, __func__, __LINE__);
        }

        LogPrintf("TLS: %s: %s():%d - setting cipher list\n", __FILE__, __func__, __LINE__);

        // Default TLSv1.3 cipher list is "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
        // Nodes will randomly choose to prefer first cipher or the second, to create diversity on the network
        // and not be in the situation where all nodes have the same list so the first is always used
        if(GetRand(100) > 50) {
            if (wolfSSL_CTX_set_cipher_list(tlsCtx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")) {
                LogPrintf("%s: Preferring TLS_AES256-GCM-SHA384\n", __func__);
                TLS_CIPHERLIST = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
            } else {
                LogPrintf("%s: Setting preferred cipher failed !!!\n", __func__);
            }
        } else {
            if (wolfSSL_CTX_set_cipher_list(tlsCtx, "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384")) {
                LogPrintf("%s: Preferring TLS_XCHACHA20_POLY1305\n", __func__);
                // WolfSSL 4.6.0 added xchacha but calls it the same ciphersuite, which causes compatibility issues
                TLS_CIPHERLIST = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384";
            } else {
                LogPrintf("%s: Setting preferred cipher failed !!!\n", __func__);
            }
        }

        if (ctxType == SERVER_CONTEXT) {
            // In case server and client prefered ciphers are different, server preference has priority
            wolfSSL_CTX_set_options(tlsCtx, SSL_OP_CIPHER_SERVER_PREFERENCE);

            LogPrintf("TLS: %s: %s():%d - setting dh callback\n", __FILE__, __func__, __LINE__);
            SSL_CTX_set_tmp_dh_callback(tlsCtx, tmp_dh_callback);
        }
  
        // No certificate verification, all should be self-signed
        wolfSSL_CTX_set_verify(tlsCtx, WOLFSSL_VERIFY_NONE, NULL);
        
        WOLFSSL_EC_KEY *ec_key = NULL;
        
        ec_key = wolfSSL_EVP_PKEY_get0_EC_KEY(mykey);

        if (ec_key != NULL && wolfSSL_PEM_write_mem_ECPrivateKey(ec_key, NULL, NULL, 0, &pem, &plen)) {
            if (wolfSSL_CTX_use_certificate(tlsCtx, mycert) > 0) {
                if (wolfSSL_CTX_use_PrivateKey_buffer(tlsCtx, pem, plen, SSL_FILETYPE_PEM) > 0) {
                    
                    free(pem);
                    
                    if (wolfSSL_CTX_check_private_key(tlsCtx)) {
                        bInitialized = true;
                    } else {
                        LogPrintf("TLS: ERROR: %s: %s: private key does not match the certificate public key\n", __FILE__, __func__);
                    }
                } else {
                    LogPrintf("TLS: ERROR: %s: %s: failed to use private key file\n", __FILE__, __func__); 
                }
            } else {
                LogPrintf("TLS: ERROR: %s: %s: failed to use certificate file\n", __FILE__, __func__);
                wolfSSL_ERR_dump_errors_fp(stderr);
            }
        }
    } else {
        LogPrintf("TLS: ERROR: %s: %s: failed to create TLS context\n", __FILE__, __func__);
    }

    if (!bInitialized) {
        if (tlsCtx) {
            wolfSSL_CTX_free(tlsCtx);
            tlsCtx = NULL;
        }
    }

    return tlsCtx;
}
/**
 * @brief generates certificate credentials.
 * 
 * @return true returns true is successful.
 * @return false returns false if an error has occured.
 */
bool TLSManager::prepareCredentials()
{
    mykey  = NULL;
    mycert = NULL;

    // Generating key and the self-signed certificate for it
    mykey = GenerateEcKey();
    if (mykey) {
        mycert = GenerateCertificate(mykey);
        if (mycert) {
            if (CheckKeyCert()) {
                LogPrintStr("TLS: New private key and self-signed certificate were generated successfully\n");
                            
                return true;
            }
            //wolfSSL_X509_free(mycert);
        }
        //wolfSSL_EVP_PKEY_free(mykey);
    }

    return false;
}

bool TLSManager::CheckKeyCert()
{
    if (!mykey) {
        LogPrintf("Key is not generated!!!\n");
        return false;
    }

    if (!mycert) {
        LogPrintf("Certificate is not generated!!!\n");
        return false;
    }        

    WOLFSSL_EC_KEY *eccKey = wolfSSL_EVP_PKEY_get1_EC_KEY(mykey);
    if (eccKey && wc_ecc_check_key((ecc_key*)eccKey->internal) == 0) {
        wolfSSL_EC_KEY_free(eccKey);
    } else {
        LogPrintf("Generated ECC key check failed!!!\n");
        return false;
    }

    int err = wolfSSL_X509_verify(mycert, mykey);
    if (err == WOLFSSL_SUCCESS) {
        return true;
    } else {
        LogPrintf("%s: x509 verification error: %d = %s\n", __func__, err);
    }
    
    LogPrintf("Generated key and certificate do not match!!!\n");
    
    return false;
}


/**
 * @brief accept a TLS connection
 * 
 * @param hSocket the TLS socket.
 * @param addr incoming address.
 * @param tls_ctx_server TLS server context.
 * @return WOLFSSL* returns pointer to the ssl object if successful, otherwise returns NULL
 */
WOLFSSL* TLSManager::accept(SOCKET hSocket, const CAddress& addr, unsigned long& err_code)
{
    LogPrint("tls", "TLS: accepting connection from %s (tid = %X)\n", addr.ToString(), pthread_self());

    char err_buffer[1024];
    err_code          = 0;
    WOLFSSL* ssl      = NULL;
    bool bAcceptedTLS = false;

    if ((ssl = wolfSSL_new(tls_ctx_server))) {
        if (wolfSSL_set_fd(ssl, hSocket)) {
            int ret = TLSManager::waitFor(SSL_ACCEPT, hSocket, ssl, (DEFAULT_CONNECT_TIMEOUT / 1000), err_code);
            if (ret == 1) {
                bAcceptedTLS = true;
            } else {
                err_code = wolfSSL_ERR_get_error();
            }
        } else {
            LogPrint("tls", "TLS: %s: failed to set file descriptor for socket!\n", __func__, addr.ToString());
        }
    } else {
        err_code = wolfSSL_ERR_get_error();
        const char* error_str = wolfSSL_ERR_error_string(err_code, err_buffer);
        LogPrint("tls", "TLS: %s: %s():%d - SSL_new failed err: %s\n", __FILE__, __func__, __LINE__, err_buffer);
    }

    if (bAcceptedTLS) {
        LogPrintf("TLS: connection from %s has been accepted (tlsv = %s 0x%04x / ssl = %s 0x%x ). Using cipher: %s\n",
            addr.ToString(), wolfSSL_get_version(ssl), wolfSSL_version(ssl), wolfSSL_OpenSSL_version(), wolfSSL_lib_version_hex(), wolfSSL_get_cipher(ssl));

        WOLFSSL_STACK *sk = wolfSSL_get_ciphers_compat(ssl); 
        for (int i = 0; i < wolfSSL_sk_SSL_CIPHER_num(sk); i++) {
            const WOLFSSL_CIPHER *c = wolfSSL_sk_SSL_CIPHER_value(sk, i);
            LogPrint("tls", "TLS: supporting cipher: %s\n", wolfSSL_CIPHER_get_name(c));
        }
    } else {
        LogPrintf("TLS: %s: %s():%d - TLS connection from %s failed (err_code 0x%X)\n", __FILE__, __func__, __LINE__, addr.ToString(), err_code);

        if (ssl) {
            SSL_free(ssl);
            ssl = NULL;
        }
    }

    return ssl;
}

/**
 * @brief Determines whether a string exists in the non-TLS address pool.
 * 
 * @param strAddr The address.
 * @param vPool Pool to search in.
 * @param cs reference to the corresponding CCriticalSection.
 * @return true returns true if address exists in the given pool.
 * @return false returns false if address doesnt exist in the given pool.
 */
bool TLSManager::isNonTLSAddr(const string& strAddr, const vector<NODE_ADDR>& vPool, CCriticalSection& cs)
{
    LOCK(cs);
    return (find(vPool.begin(), vPool.end(), NODE_ADDR(strAddr)) != vPool.end());
}

/**
 * @brief Removes non-TLS node addresses based on timeout.
 * 
 * @param vPool 
 * @param cs 
 */
void TLSManager::cleanNonTLSPool(std::vector<NODE_ADDR>& vPool, CCriticalSection& cs)
{
    LOCK(cs);

    vector<NODE_ADDR> vDeleted;

    BOOST_FOREACH (NODE_ADDR nodeAddr, vPool) {
        if ((GetTimeMillis() - nodeAddr.time) >= 900000) {
            vDeleted.push_back(nodeAddr);
            LogPrint("tls", "TLS: Node %s is deleted from the non-TLS pool\n", nodeAddr.ipAddr);
        }
    }

    BOOST_FOREACH (NODE_ADDR nodeAddrDeleted, vDeleted) {
        vPool.erase(
            remove(
                vPool.begin(),
                vPool.end(),
                nodeAddrDeleted),
            vPool.end());
    }
}

/**
 * @brief Handles send and recieve functionality in TLS Sockets.
 * 
 * @param pnode reference to the CNode object.
 * @param fdsetRecv 
 * @param fdsetSend 
 * @param fdsetError 
 * @return int returns -1 when socket is invalid. returns 0 otherwise.
 */
int TLSManager::threadSocketHandler(CNode* pnode, fd_set& fdsetRecv, fd_set& fdsetSend, fd_set& fdsetError)
{
    //
    // Receive
    //
    bool recvSet = false, sendSet = false, errorSet = false;

    {
        LOCK(pnode->cs_hSocket);

        if (pnode->hSocket == INVALID_SOCKET)
            return -1;

        recvSet = FD_ISSET(pnode->hSocket, &fdsetRecv);
        sendSet = FD_ISSET(pnode->hSocket, &fdsetSend);
        errorSet = FD_ISSET(pnode->hSocket, &fdsetError);
    }

    if (recvSet || errorSet) {
        TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
        if (lockRecv) {
            {
                // typical socket buffer is 8K-64K
                // maximum record size is 16kB for SSLv3/TLSv1
                char pchBuf[0x10000];
                bool bIsSSL = false;
                int nBytes = 0, nRet = 0;

                {
                    LOCK(pnode->cs_hSocket);

                    if (pnode->hSocket == INVALID_SOCKET) {
                        LogPrint("tls", "Receive: connection with %s is already closed\n", pnode->addr.ToString());
                        return -1;
                    }

                    bIsSSL = (pnode->ssl != NULL);

                    if (bIsSSL) {
                        wolfSSL_ERR_clear_error(); // clear the error queue, otherwise we may be reading an old error that occurred previously in the current thread
                        nBytes = wolfSSL_read(pnode->ssl, pchBuf, sizeof(pchBuf));
                        nRet = wolfSSL_get_error(pnode->ssl, nBytes);
                    } else {
                        nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                        nRet = WSAGetLastError();
                    }
                }

                if (nBytes > 0) {
                    if (!pnode->ReceiveMsgBytes(pchBuf, nBytes))
                        pnode->CloseSocketDisconnect();
                    pnode->nLastRecv = GetTime();
                    pnode->nRecvBytes += nBytes;
                    pnode->RecordBytesRecv(nBytes);
                } else if (nBytes == 0) {

                    if (bIsSSL) {
                        unsigned long error = ERR_get_error();
                        const char* error_str = ERR_error_string(error, NULL);
                        LogPrint("tls", "TLS: WARNING: %s: %s():%d - SSL_read err: %s\n",
                            __FILE__, __func__, __LINE__, error_str);
                    }
                    // socket closed gracefully (peer disconnected)
                    if (!pnode->fDisconnect)
                        LogPrint("tls", "socket closed (%s)\n", pnode->addr.ToString());
                    pnode->CloseSocketDisconnect();

                } else if (nBytes < 0) {
                    // error
                    if (bIsSSL) {
                        if (nRet != WOLFSSL_ERROR_WANT_READ && nRet != WOLFSSL_ERROR_WANT_WRITE)
                        {
                            if (!pnode->fDisconnect)
                                LogPrintf("TLS: ERROR: SSL_read %s\n", ERR_error_string(nRet, NULL));
                            pnode->CloseSocketDisconnect();

                            unsigned long error = ERR_get_error();
                            const char* error_str = ERR_error_string(error, NULL);
                            LogPrint("tls", "TLS: WARNING: %s: %s():%d - SSL_read - code[0x%x], err: %s\n",
                                __FILE__, __func__, __LINE__, nRet, error_str);

                        } else {
                            // preventive measure from exhausting CPU usage
                            MilliSleep(1); // 1 msec
                        }
                    } else {
                        if (nRet != WSAEWOULDBLOCK && nRet != WSAEMSGSIZE && nRet != WSAEINTR && nRet != WSAEINPROGRESS) {
                            if (!pnode->fDisconnect)
                                LogPrintf("TLS: ERROR: socket recv %s\n", NetworkErrorString(nRet));
                            pnode->CloseSocketDisconnect();
                        }
                    }
                }
            }
        }
    }

    // Send
    if (sendSet) {
        TRY_LOCK(pnode->cs_vSend, lockSend);
        if (lockSend)
            SocketSendData(pnode);
    }

    return 0;
}

/**
 * @brief Initialization of the server and client contexts
 * 
 * @return true returns True if successful.
 * @return false returns False if an error has occured.
 */
bool TLSManager::initialize()
{
    bool bInitializationStatus = false;
    
    // Initialization routines for the WolfSSL library
    wolfSSL_load_error_strings();
    wolfSSL_ERR_load_crypto_strings();
    wolfSSL_library_init();

    // Initialization of the server and client contexts
    if ((tls_ctx_server = TLSManager::initCtx(SERVER_CONTEXT))) {
        if ((tls_ctx_client = TLSManager::initCtx(CLIENT_CONTEXT))) {
            LogPrint("tls", "TLS: contexts are initialized\n");
            bInitializationStatus = true;
        } else {
            LogPrintf("TLS: ERROR: %s: %s: failed to initialize TLS client context\n", __FILE__, __func__);
            wolfSSL_CTX_free (tls_ctx_server);
        }
    } else {
        LogPrintf("TLS: ERROR: %s: %s: failed to initialize TLS server context\n", __FILE__, __func__);
    }

    return bInitializationStatus;
}
}
