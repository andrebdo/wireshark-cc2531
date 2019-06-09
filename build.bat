if "%vcinstalldir%"=="" call "c:\program files (x86)\microsoft visual studio 14.0\vc\bin\x86_amd64\vcvarsx86_amd64.bat"
cl.exe /nologo /O2 cc2531.c setupapi.lib winusb.lib
