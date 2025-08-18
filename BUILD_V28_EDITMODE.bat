@echo off
echo =========================================
echo Building v28.0.0 - EDIT MODE FIX
echo Proper Layout Edit Mode Support
echo =========================================
echo.

REM Clean up
if exist foo_artist_bio.dll del foo_artist_bio.dll
if exist *.obj del *.obj

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo Compiling v28.0.0 EDIT MODE FIX...
cl /c /EHsc /MD /O2 /std:c++17 /DNDEBUG /DUNICODE /D_UNICODE /DFOOBAR2000_TARGET_VERSION=82 /I"SDK-2025-03-07" /I"SDK-2025-03-07\foobar2000" /I"SDK-2025-03-07\foobar2000\SDK" /I"SDK-2025-03-07\pfc" artist_bio_v14_FINAL.cpp /Foartist_bio_v28.obj

if not exist artist_bio_v28.obj (
    echo Compilation failed!
    pause
    exit /b 1
)

echo Linking...
link /DLL /OUT:foo_artist_bio.dll artist_bio_v28.obj "SDK-2025-03-07\foobar2000\foobar2000_component_client\x64\Release\foobar2000_component_client.lib" "SDK-2025-03-07\foobar2000\SDK\x64\Release\foobar2000_SDK.lib" "SDK-2025-03-07\pfc\x64\Release\pfc.lib" "SDK-2025-03-07\foobar2000\shared\shared-x64.lib" kernel32.lib user32.lib gdi32.lib gdiplus.lib shell32.lib winhttp.lib wininet.lib urlmon.lib shlwapi.lib ole32.lib oleaut32.lib advapi32.lib windowscodecs.lib /NODEFAULTLIB:LIBCMT

if not exist foo_artist_bio.dll (
    echo Linking failed!
    pause
    exit /b 1
)

echo Creating component package...

REM Create info file
echo Artist Bio Viewer v28.0.0> info.txt
echo Edit mode menu fix + All features>> info.txt

REM Create the component package
powershell -Command "Compress-Archive -Path 'foo_artist_bio.dll', 'info.txt' -DestinationPath 'temp.zip' -Force"

if exist temp.zip (
    move /Y temp.zip foo_artist_bio_v28_EDITMODE.fb2k-component >nul
    echo.
    echo =========================================
    echo SUCCESS! Component created:
    echo foo_artist_bio_v28_EDITMODE.fb2k-component
    echo =========================================
    echo.
    echo Version 28.0.0 EDIT MODE FIX:
    echo.
    echo IMPROVEMENTS:
    echo - Edit mode detection added
    echo - Context menu properly handled in edit mode
    echo - Menu methods callable by host
    echo - Context menu service registered
    echo.
    echo ALL FEATURES:
    echo - Image scaling works perfectly
    echo - Draggable dividers in both modes
    echo - Unicode text support
    echo - No text cutoff
    echo - Stats display correctly
    echo - Double-click layout switching
    echo - Right-click context menu
    echo.
    echo INSTALL:
    echo 1. Close foobar2000 completely
    echo 2. Remove ALL old versions
    echo 3. Install this component
    echo 4. Restart foobar2000
    echo.
    echo TEST:
    echo - Enable layout editing mode in foobar2000
    echo - Right-click on the Artist Bio panel
    echo - Check if menu items appear properly
    echo.
)

pause