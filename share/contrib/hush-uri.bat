@Echo On
Title Reg Converter v1.1 & Color 1A
REM ~ call :IsAdmin

call :RegExport
Exit

:RegExport
Set RegFile="%Temp%\~etsaclu.tmp"

Set "hush=%~dp0"
set "hush=%hush:\=\\%"

If Exist %RegFile% (
 Attrib -R -S -H %RegFile% &  Del /F /Q %RegFile%
 If Exist %RegFile% cls & Echo Could not delete file %RegFile% & Pause
)
> %RegFile% Echo Windows Registry Editor Version 5.00
>> %RegFile% Echo.
>> %RegFile% Echo [HKEY_CLASSES_ROOT\hush]
>> %RegFile% Echo @="URL:hush protocol"
>> %RegFile% Echo "URL Protocol"=""
>> %RegFile% Echo.
>> %RegFile% Echo [HKEY_CLASSES_ROOT\hush\DefaultIcon]
>> %RegFile% Echo @="silentdragon.exe"
>> %RegFile% Echo.
>> %RegFile% Echo [HKEY_CLASSES_ROOT\hush\Shell]
>> %RegFile% Echo.
>> %RegFile% Echo [HKEY_CLASSES_ROOT\hush\Shell\Open]
>> %RegFile% Echo.
>> %RegFile% Echo [HKEY_CLASSES_ROOT\hush\Shell\Open\Command]
>> %RegFile% Echo @="%hush%silentdragon.exe \"%%1\""

Start /Wait %systemroot%\Regedit.exe /S %RegFile%
Del %RegFile%
goto:eof

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof

