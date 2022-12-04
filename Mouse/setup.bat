IF NOT EXIST %HOMEDRIVE%%HOMEPATH%\.Abhisoft\Mouse (
  MD %HOMEDRIVE%%HOMEPATH%\.Abhisoft\Mouse
)
IF NOT EXIST %HOMEDRIVE%%HOMEPATH%\.Abhisoft\Mouse\mouse.exe (
  powershell -Command "Invoke-WebRequest https://github.com/thebytecoders/WorkEasy/raw/main/Mouse/mouse.exe -OutFile "%HOMEDRIVE%%HOMEPATH%"\.Abhisoft\Mouse\mouse.exe"
)
IF NOT EXIST %HOMEDRIVE%%HOMEPATH%\.Abhisoft\Mouse\mouse-controller.cmd (
  powershell -Command "Invoke-WebRequest https://raw.githubusercontent.com/thebytecoders/WorkEasy/main/Mouse/mouse-controller.cmd -OutFile "%HOMEDRIVE%%HOMEPATH%"\.Abhisoft\Mouse\mouse-controller.cmd"
)
echo Set objShell = WScript.CreateObject("WScript.Shell")>>"%TEMP%\temp-mouse-config.vbs"
echo Set lnk = objShell.CreateShortcut(objShell.SpecialFolders("Desktop")^&"\keep-me-awake.lnk")>>"%TEMP%\temp-mouse-config.vbs"
echo lnk.TargetPath = "%HOMEDRIVE%%HOMEPATH%\.Abhisoft\Mouse\mouse-controller.cmd">>"%TEMP%\temp-mouse-config.vbs"
echo lnk.WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%\.Abhisoft\Mouse">>"%TEMP%\temp-mouse-config.vbs"
echo lnk.Save>>"%TEMP%\temp-mouse-config.vbs"
cscript /nologo "%TEMP%\temp-mouse-config.vbs"
del "%TEMP%\temp-mouse-config.vbs"
del "%~f0"