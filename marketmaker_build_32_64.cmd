@echo off

@REM Check for Visual Studio
call set "VSPATH="
if defined VS140COMNTOOLS ( if not defined VSPATH (
 call set "VSPATH=%%VS140COMNTOOLS%%"
) )

@REM check if we already have the tools in the environment
if exist "%VCINSTALLDIR%" (
 goto compile
)

if not defined VSPATH (
 echo You need Microsoft Visual Studio 15 installed
 pause
 exit
)

@REM set up the environment
if exist "%VSPATH%..\..\vc\vcvarsall.bat" (
 call "%%VSPATH%%..\..\vc\vcvarsall.bat" amd64
 goto compile
)

echo Unable to set up the environment
pause
exit

:compile
rem MSBuild /help
MSBuild marketmaker.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
MSBuild marketmaker.sln /t:Rebuild /p:Configuration=Release /p:Platform=x86

rem Obtain version number and latest git commit number

FOR /F "tokens=* USEBACKQ" %%F IN (`find /i "LP_MAJOR_VERSION" "iguana\exchanges\LP_include.h"`) DO (
SET LP_MAJOR_VERSION_STR=%%F
)
FOR /F "tokens=* USEBACKQ" %%F IN (`find /i "LP_MINOR_VERSION" "iguana\exchanges\LP_include.h"`) DO (
SET LP_MINOR_VERSION_STR=%%F
)
FOR /F "tokens=* USEBACKQ" %%F IN (`find /i "LP_BUILD_NUMBER" "iguana\exchanges\LP_include.h"`) DO (
SET LP_BUILD_NUMBER_STR=%%F
)

for /f delims^=^"^ tokens^=2 %%a in ('echo %LP_MAJOR_VERSION_STR%') do (
set LP_MAJOR_VERSION=%%a
)
for /f delims^=^"^ tokens^=2 %%a in ('echo %LP_MINOR_VERSION_STR%') do (
set LP_MINOR_VERSION=%%a
)
for /f delims^=^"^ tokens^=2 %%a in ('echo %LP_BUILD_NUMBER_STR%') do (
set LP_BUILD_NUMBER=%%a
)

rem Check if git command exist and if does - receive latest GIT_COMMIT
git --version >nul 2>&1 && (
	for /f "tokens=1" %%a in ('git rev-parse --short HEAD') do (
		set GIT_COMMIT=_%%a
	)
) || (
    set GIT_COMMIT=
)

rem echo Marketmaker_%LP_MAJOR_VERSION%.%LP_MINOR_VERSION%_%LP_BUILD_NUMBER%%GIT_COMMIT%

rem Using to add in marketmaker_release.7z
set host=%COMPUTERNAME%
IF "%host%"=="VM-81" (
    mkdir package_content\win32
    mkdir package_content\win64
    copy /y Release\marketmaker.exe package_content\win32
    copy /y x64\Release\marketmaker.exe package_content\win64
    copy /y x64\Release\libcurl.dll package_content\win64
    copy /y x64\Release\nanomsg.dll package_content\win64
    echo Marketmaker_%LP_MAJOR_VERSION%.%LP_MINOR_VERSION%_%LP_BUILD_NUMBER%%GIT_COMMIT% > package_content\version.txt
    cd package_content
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z win32\marketmaker.exe
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z win64\marketmaker.exe
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z win64\libcurl.dll
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z win64\nanomsg.dll
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z version.txt
    cd ..
    rd package_content /s /q
    )
