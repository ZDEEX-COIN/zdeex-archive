@call :GET_CURRENT_DIR
@cd %THIS_DIR%
hushd.exe -ac_name=DRAGONX -ac_algo=randomx -ac_halving=3500000 -ac_reward=300000000 -ac_blocktime=36 -ac_private=1 -addnode=176.126.87.241 %*
@goto :EOF

:GET_CURRENT_DIR
@pushd %~dp0
@set THIS_DIR=%CD%
@popd
@goto :EOF
