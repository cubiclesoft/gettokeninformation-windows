@echo off
cls

cl /Ox gettokeninformation.cpp utf8/*.cpp json/*.cpp -D_USING_V110_SDK71_ -DSUBSYSTEM_CONSOLE /link /FILEALIGN:512 /OPT:REF /OPT:ICF /INCREMENTAL:NO /subsystem:console,5.01 user32.lib advapi32.lib secur32.lib credui.lib ole32.lib /out:gettokeninformation.exe
cl /Ox gettokeninformation.cpp utf8/*.cpp json/*.cpp -D_USING_V110_SDK71_ -DSUBSYSTEM_WINDOWS /link /FILEALIGN:512 /OPT:REF /OPT:ICF /INCREMENTAL:NO /subsystem:windows,5.01 user32.lib shell32.lib advapi32.lib secur32.lib credui.lib ole32.lib /out:gettokeninformation-win.exe
