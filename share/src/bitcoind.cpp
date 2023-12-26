// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
#include "clientversion.h"
#include "rpc/server.h"
#include "init.h"
#include "main.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <stdio.h>

#ifdef _WIN32
#define frpintf(...)
#define printf(...)
#endif

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the GPLv3 license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

static bool fDaemon;
#include "hush_defs.h"
#define HUSH_SMART_CHAIN_MAXLEN 65
extern char SMART_CHAIN_SYMBOL[HUSH_SMART_CHAIN_MAXLEN];
extern int32_t ASSETCHAINS_BLOCKTIME;
extern uint64_t ASSETCHAINS_CBOPRET;
void hush_passport_iteration();
int32_t hush_longestchain();
void hush_cbopretupdate(int32_t forceflag);
CBlockIndex *hush_chainactive(int32_t height);

void WaitForShutdown(boost::thread_group* threadGroup)
{
    int32_t i,height; CBlockIndex *pindex; bool fShutdown = ShutdownRequested(); const uint256 zeroid;
    // Tell the main threads to shutdown.

    if ( ASSETCHAINS_CBOPRET != 0 ) {
        hush_pricesinit();
	}

    while (!fShutdown)
    {
        //fprintf(stderr,"call passport iteration\n");
        if ( SMART_CHAIN_SYMBOL[0] == 0 )
        {
            if ( HUSH_NSPV_FULLNODE )
                hush_passport_iteration();
            for (i=0; i<10; i++)
            {
                fShutdown = ShutdownRequested();
                if ( fShutdown != 0 )
                    break;
                MilliSleep(1000);
            }
        } else {
            //hush_longestchain();
            if ( ASSETCHAINS_CBOPRET != 0 )
                hush_cbopretupdate(0);
            for (i=0; i<=ASSETCHAINS_BLOCKTIME/5; i++)
            {
                fShutdown = ShutdownRequested();
                if ( fShutdown != 0 )
                    break;
                MilliSleep(1000);
            }
        }
        fShutdown = ShutdownRequested();
    }
    //fprintf(stderr,"%s: fShutdown=%d\n", __FUNCTION__, fShutdown);

    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

// Start
extern int32_t IS_HUSH_NOTARY,USE_EXTERNAL_PUBKEY;
extern uint32_t ASSETCHAIN_INIT;
extern std::string NOTARY_PUBKEY;
int32_t hush_is_issuer();
void hush_passport_iteration();

bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;


    // Parameters
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version"))
    {
        std::string strUsage = _("Hush Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n" + PrivacyInfo();

        if (mapArgs.count("-version"))
        {
            strUsage += LicenseInfo();
        } else {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  hushd [options]                     " + _("Start a Hush Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try
    {
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        if (!SelectParamsFromCommandLine()) {
            fprintf(stderr, "Error: Invalid combination of -regtest and -testnet.\n");
            return false;
        }
        void hush_args(char *argv0);
        hush_args(argv[0]);
        void chainparams_commandline();
        chainparams_commandline();

        fprintf(stderr,"hush_args.(%s) NOTARY_PUBKEY.(%s) argc=%d\n",argv[0],NOTARY_PUBKEY.c_str(), argc);
        printf("initialized %s at %u\n",SMART_CHAIN_SYMBOL,(uint32_t)time(NULL));
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
			fprintf(stderr, "%s reading config file\n", __FUNCTION__);
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const missing_hush_conf& e) {
            fprintf(stderr,
                (_("Before starting hushd, you need to create a configuration file:\n"
                   "%s\n"
                   "It can be completely empty! That indicates you are happy with the default\n"
                   "configuration of hushd. But requiring a configuration file to start ensures\n"
                   "that hushd won't accidentally compromise your privacy if there was a default\n"
                   "option you needed to change.\n"
                   "\n"
                   "You can look at the example configuration file for suggestions of default\n"
                   "options that you may want to change. It should be in one of these locations,\n"
                   "depending on how you installed Hush\n") +
                 _("- Source code:  %s\n"
                   "- .deb package: %s\n")).c_str(),
                GetConfigFile().string().c_str(),
                "contrib/debian/examples/HUSH3.conf",
                "/usr/share/doc/hush/examples/HUSH3.conf",
                "https://git.hush.is/hush/hush3/src/branch/master/contrib/debian/examples/HUSH3.conf");
            return false;
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }

        // Command-line RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++) {
            // detect accidental use of RPC in hushd
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "hush:")) {
                fCommandLine = true;
			}
		}

        if (fCommandLine)
        {
            fprintf(stderr, "Error: Ooops! There is no RPC client functionality in hushd. Use the hush-cli utility instead.\n");
            exit(EXIT_FAILURE);
        }

#ifndef _WIN32
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            fprintf(stdout, "Hush %s server starting\n",SMART_CHAIN_SYMBOL);

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

		//fprintf(stderr,"%s: Running AppInit2()\n", __FUNCTION__);
        fRet = AppInit2(threadGroup, scheduler);
		//fprintf(stderr,"%s: Finished AppInit2(), fRet=%d\n", __FUNCTION__, fRet);
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }
    if (!fRet)
    {
		//fprintf(stderr,"%s: Interrupting threadGroup\n", __FUNCTION__);
        Interrupt(threadGroup);
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else {
		//fprintf(stderr,"%s: Waiting for Shutdown\n", __FUNCTION__);
        WaitForShutdown(&threadGroup);
    }
    Shutdown();

    return fRet;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();

    // Connect bitcoind signal handlers
    noui_connect();

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}
