// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

namespace hush
{
    typedef enum { SSL_ACCEPT, SSL_CONNECT, SSL_SHUTDOWN } SSLConnectionRoutine;
    typedef enum { CLIENT_CONTEXT, SERVER_CONTEXT } TLSContextType;
}
