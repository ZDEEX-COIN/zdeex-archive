// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "tlsenums.h"
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include "../util.h"
#include "../net.h"
#include "sync.h"
#include <boost/filesystem/path.hpp>
#include <boost/foreach.hpp>
#include <boost/signals2/signal.hpp>
#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

using namespace std;

namespace hush
{
typedef struct _NODE_ADDR {
    std::string ipAddr;
    int64_t time; // time in msec, of an attempt to connect via TLS

    _NODE_ADDR(std::string _ipAddr, int64_t _time = 0) : ipAddr(_ipAddr), time(_time) {}
bool operator==(const _NODE_ADDR b) const
{
    return (ipAddr == b.ipAddr);
}
} NODE_ADDR, *PNODE_ADDR;

// A class to wrap some of hush specific TLS functionalities used in the net.cpp
class TLSManager
{
public:
    /*  This is set as a custom error number which is not an error in SSL protocol.
        A true (not null) SSL error returned by ERR_get_error() consists of a library number,
        function code and reason code. */
    static const long SELECT_TIMEDOUT = 0xFFFFFFFF;

    int waitFor(SSLConnectionRoutine eRoutine, SOCKET hSocket, WOLFSSL* ssl, int timeoutSec, unsigned long& err_code);

    WOLFSSL* connect(SOCKET hSocket, const CAddress& addrConnect, unsigned long& err_code);
    WOLFSSL_CTX* initCtx(TLSContextType ctxType);
    bool prepareCredentials();
    WOLFSSL* accept(SOCKET hSocket, const CAddress& addr, unsigned long& err_code);
    bool isNonTLSAddr(const string& strAddr, const vector<NODE_ADDR>& vPool, CCriticalSection& cs);
    void cleanNonTLSPool(std::vector<NODE_ADDR>& vPool, CCriticalSection& cs);
    int threadSocketHandler(CNode* pnode, fd_set& fdsetRecv, fd_set& fdsetSend, fd_set& fdsetError);
    bool initialize();
    bool CheckKeyCert();
};
}
