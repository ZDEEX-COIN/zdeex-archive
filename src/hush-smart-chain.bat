:: Copyright (c) 2016-2023 The Hush developers
:: Distributed under the GPLv3 software license, see the accompanying
:: file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
@call :GET_CURRENT_DIR
@cd %THIS_DIR%
hushd %*
@goto :EOF

:GET_CURRENT_DIR
@pushd %~dp0
