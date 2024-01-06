@call :GET_CURRENT_DIR
@cd %THIS_DIR%
hush-cli.exe -ac_name=DRAGONX %*
@goto :EOF

:GET_CURRENT_DIR
@pushd %~dp0
@set THIS_DIR=%CD%
@popd
@goto :EOF
