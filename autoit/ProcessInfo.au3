#include <Security.au3>
#include <WinAPI.au3>
#include <WinAPIProc.au3>
#include <Process.au3>

Global Const $SE_PRIVILEGE_DISABLED = 0x00000000
Global Const $SE_PRIVILEGE_DEFAULT = 0x00000001
Global Const $SE_PRIVILEGE_DEFAULT_ENABLED = 0x00000003
Global Const $TOKEN_MAXIMUM_ALLOWED = 0x02000000
Global Const $WTS_CURRENT_SERVER_HANDLE = 0
Global Const $WTS_ANY_SESSION = -2
Global Const $WTS_PROCESS_INFO_EX = 1
Global $output, $protectedPids
Global $protectedCount = 0, $totalProcess = 0


Func _GetProcessChilds($pid)
	Local $ar, $tmpOut
	$ar = _WinAPI_EnumChildProcess($pid)
	If IsArray($ar) Then
		$tmpOut = "[+] Childs       : " & $ar[0][0] & @CRLF
		For $i = 1 To $ar[0][0]
			$tmpOut &= "    [*] " & $ar[$i][0] & " -> " & $ar[$i][1] & @CRLF
		Next
	EndIf
	Return $tmpOut
EndFunc   ;==>_GetProcessChilds



Func _GetProcessPath($hProcess)
	Local $aCall, $d
	$d = DllStructCreate("char[256]")
	$aCall = DllCall("kernel32.dll", "ptr", "QueryFullProcessImageName", "ptr", $hProcess, "dword", 0, "ptr", DllStructGetPtr($d), "dword*", 256)
	Return "[+] Process Path : " & DllStructGetData($d, 1) & @CRLF
EndFunc   ;==>_GetProcessPath



Func _GetProcessType($hProcess)
	Local $tmpOut, $aCall
	$tmpOut = "[+] Process Type : "
	$aCall = DllCall("kernel32.dll", "bool", "IsWow64Process", "handle", $hProcess, "bool*", 0)
	If $aCall[2] Then
		$tmpOut &= "32bit" & @CRLF
	Else
		$tmpOut &= "64bit" & @CRLF
	EndIf
	Return $tmpOut
EndFunc   ;==>_GetProcessType



Func _GetAce($pACL, $dwIndex)
	If Not _IsValidAcl($pACL) Then Return
	Local $aCall, $ACE_HEADER, $array[4]
	$aCall = DllCall("advapi32.dll", "int", "GetAce", "ptr", $pACL, "dword", $dwIndex, "ptr*", 0)
	$ACE_HEADER = DllStructCreate("byte AceType;byte AceFlag;word AceSize;dword AccessMask;byte SID[256]", $aCall[3])
	$array[0] = DllStructGetData($ACE_HEADER, 1)
	$array[1] = DllStructGetData($ACE_HEADER, 2)
	$array[2] = DllStructGetData($ACE_HEADER, 3)
	$array[3] = DllStructGetPtr($ACE_HEADER, 5)
	Return $array
EndFunc   ;==>_GetAce



Func _IsValidAcl($pACL)
	Local $aCall
	$aCall = DllCall("advapi32.dll", "bool", "IsValidAcl", "ptr", $pACL)
	Return $aCall[0]
EndFunc   ;==>_IsValidAcl



Func _GetTokenDefaultDacl($hToken)
	Local $aCall, $ptrSize, $pACL, $ACL_SIZE_INFORMATION, $aceCount, $tmpOut
	$tBuffer = _GetTokenInformation($hToken, $TOKENDEFAULTDACL)
	If Not DllStructGetData($tBuffer, 1) Then Return "[!] ACL Protected, skipping" & @CRLF
	$_TOKEN_DEFAULT_DACL = DllStructCreate("ptr DefaultDacl;", DllStructGetPtr($tBuffer))
	$pACL = DllStructGetData($_TOKEN_DEFAULT_DACL, 1)
	If Not _IsValidAcl($pACL) Then Return ConsoleWrite("ACL Invalid" & @CRLF)
	$_ACL = DllStructCreate("byte ACLRevision;byte Sbz1;word AclSize;word AceCount;word Sbz2;", $pACL)
	$aceCount = DllStructGetData($_ACL, "AceCount")
	$tmpOut = "[+] ACL Info" & @CRLF & "    ACLSize      : " & DllStructGetData($_ACL, 3) & @CRLF & "    AceCount     : " & DllStructGetData($_ACL, "AceCount") & @CRLF
	For $i = 0 To $aceCount - 1
		$aceInfo = _GetAce($pACL, $i)
		$tmpOut &= "    -------------------------------" & @CRLF
		$tmpOut &= "    AceType      : " & $aceInfo[0] & @CRLF & "    AceFlag      : " & $aceInfo[1] & _
				@CRLF & "    AceSize      : " & $aceInfo[2] & @CRLF & "    SID          : "
		$bCall = _Security__LookupAccountSid($aceInfo[3])
		If IsArray($bCall) Then
			If $bCall[1] Then $tmpOut &= $bCall[1] & "\"
			$tmpOut &= $bCall[0]
		EndIf
		$tmpOut &= @CRLF
	Next
	$tmpOut &= "    -------------------------------" & @CRLF
	Return $tmpOut
EndFunc   ;==>_GetTokenDefaultDacl



Func _GetTokenPrimaryGroup($hToken)
	Local $aCall, $pSid, $tmpOut, $bCall
	$aCall = _GetTokenInformation($hToken, $TOKENPRIMARYGROUP)
	$pSid = DllStructCreate("ptr PSID", DllStructGetPtr($aCall))
	$tmpOut = "[+] Token Group  : "
	$bCall = _Security__LookupAccountSid(DllStructGetData($pSid, 1))
	If IsArray($bCall) Then
		If $bCall[1] Then $tmpOut &= $bCall[1] & "\"
		$tmpOut &= $bCall[0]
	EndIf
	Return $tmpOut&@CRLF
EndFunc   ;==>_GetTokenPrimaryGroup



Func _GetTokenElevation($hToken)
	Local $aCall,$eType,$tmpOut
	$aCall = _GetTokenInformation($hToken, $TOKENELEVATION)
	$eType = Int(DllStructGetData($aCall,1))
	Switch $eType
		Case 0
			$tmpOut = "[+] TokElevated  : False"
		Case 1
			$tmpOut = "[+] TokElevated  : True"
	EndSwitch
	Return $tmpOut&@CRLF
EndFunc


;unused for now
Func _GetTokenGroupsAndPrivileges($hToken)
	Local $aCall,$struct,$tBuffer
	$aCall = _GetTokenInformation($hToken, $TOKENGROUPSANDPRIVILEGES)
	$struct = "int SidCount;int SidLength;ptr SID;dword SIDAttributes;int RestrictedSidCount;int RestrictedSidLength;" & _
			"ptr pRestrictedSids;dword RestrictedSids;int PrivilegeCount;int PrivilegeLength;ptr pPrivileges;dword Privileges;" & _
			"int64 AuthenticationId"
	$tBuffer = DllStructCreate($struct,DllStructGetPtr($aCall))
	Return $tBuffer
EndFunc


;unused for now
Func _GetTokenSource($hToken)
	Local $aCall, $tBuffer
	$aCall = _GetTokenInformation($hToken, $TOKENPRIMARYGROUP)
	$tBuffer = DllStructCreate("char SourceName[8];int64 SourceIdentifier", DllStructGetPtr($aCall))
	Return $tBuffer
EndFunc   ;==>_GetTokenSource


;unused for now
Func _GetTokenStatistics($hToken)
	Local $aCall, $struct,$array[5]
	$aCall = _GetTokenInformation($hToken, $TOKENSTATISTICS)
	$struct = "int64 TokenId;int64 AuthenticationId;int64 ExpirationTime;int TokenType; int ImpersonationLevel;" & _
			"dword DynamicCharged;dword DynamicAvailable;int GroupCount;int PrivilegeCount;int64 ModifiedId"
	$TOKEN_STATISTICS = DllStructCreate($struct,DllStructGetPtr($aCall))
	$array[0] = DllStructGetData($TOKEN_STATISTICS,"TokenId")
	$array[1] = DllStructGetData($TOKEN_STATISTICS,"AuthenticationId")
	$array[2] = DllStructGetData($TOKEN_STATISTICS,"ExpirationTime")
	$array[3] = DllStructGetData($TOKEN_STATISTICS,"GroupCount")
	$array[4] = DllStructGetData($TOKEN_STATISTICS,"PrivilegeCount")
	Return $array
EndFunc


;unused for now
Func _GetTokenRestrictedSids($hToken)
	Local $aCall, $TOKEN_GROUPS,$array[5]
	$aCall = _GetTokenInformation($hToken, 11)
	$TOKEN_GROUPS = DllStructCreate("dword GroupCount;ptr Sid;dword Attributes",DllStructGetPtr($aCall))
	;_TODO
	Return
EndFunc



Func _GetTokenType($hToken)
	Local $aCall, $tmpOut
	$aCall = DllStructGetData(_GetTokenInformation($hToken, $TOKENTYPE), 1)
	$tmpOut = "[+] Token Type   : "
	Switch $aCall
		Case 0
			$tmpOut &= "Impersonation"
		Case 1
			$tmpOut &= "Primary"
	EndSwitch
	Return $tmpOut&@CRLF
EndFunc   ;==>_GetTokenType


;SECURITY_IMPERSONATION_LEVEL (SIL)
Func _GetTokenImpersonationLevel($hToken)
	Local $aCall, $tmpOut
	$aCall = DllStructGetData(_GetTokenInformation($hToken, $TOKENTYPE), 1)
	$tmpOut = "[+] Token SIL    : "
	Switch $aCall
		Case 0
			$tmpOut &= "SecurityAnonymous"
		Case 1
			$tmpOut &= "SecurityIdentification"
		Case 2
			$tmpOut &= "SecurityImpersonation"
		Case 3
			$tmpOut &= "SecurityDelegation"
	EndSwitch
	Return $tmpOut&@CRLF
EndFunc



;unused for now
Func _GetTokenPSid($hToken, $iType)
	Local $aCall = _GetTokenInformation($hToken, $iType)
	$pSid = DllStructCreate("ptr PSID", DllStructGetPtr($aCall))
	$tempPtr = DllStructCreate("ptr")
	$ptrSize = DllStructGetSize($tempPtr)
	$rawSid = BinaryMid($aCall, $ptrSize * 2 + 1, BinaryLen($aCall))
	$mem = DllStructCreate("byte Attributes[" & BinaryLen($rawSid) & "]")
	DllStructSetData($mem, "Attributes", $rawSid)
	$pSid = DllStructGetPtr($mem)
	Return _Security__SidToStringSid($pSid)
EndFunc   ;==>_GetTokenPSid



Func _GetTokenGroups($hToken)
	Local $tmpVar, $tBuffer, $groupCount, $offset, $tmpOut, $tempPtr, $ptrSize
	Local $attrib, $tPtrSid, $ptr, $bCall
	$tmpVar = _Security__GetTokenInformation($hToken, $TOKENGROUPS)
	$tBuffer = DllStructGetData($tmpVar, 1)
	$groupCount = Int(BinaryMid($tBuffer, 1, 4))
	If Not $groupCount Then Return ""
	$offset = 0
	$tmpOut = "[+] Token is part of the following "&$groupCount&" groups" & @CRLF
	For $i = 1 To $groupCount
		$tempPtr = DllStructCreate("ptr")
		$ptrSize = DllStructGetSize($tempPtr) ; tmp pointers to determine size for 32 or 64bits
		If $offset == 0 Then $offset = $ptrSize + 1
		$tPtrSid = BinaryMid($tBuffer, $offset, $ptrSize)
		$attrib = BinaryMid($tBuffer, $offset + $ptrSize, $ptrSize)
		$ptr = DllStructCreate("ptr pSID;ptr Attributes")
		DllStructSetData($ptr, "pSID", Int($tPtrSid))
		DllStructSetData($ptr, "Attributes", Int($attrib))
		$bCall = _Security__LookupAccountSid(DllStructGetData($ptr, "pSID"))
		If IsArray($bCall) Then
			$tmpOut &= "    [*] "
			If $bCall[1] Then $tmpOut &= $bCall[1] & "\"
			$tmpOut &= $bCall[0] & @CRLF
		EndIf
		$offset += 2 * $ptrSize
	Next
	Return $tmpOut
EndFunc   ;==>_GetTokenGroups



Func _GetTokenOwner($hToken)
	Local $aCall, $bCall, $tmpPtr, $ptrSize, $rawSid, $mem, $pSid
	$aCall = DllStructGetData(_GetTokenInformation($hToken, $TOKENOWNER), 1)
	$tmpPtr = DllStructCreate("PTR")
	$ptrSize = DllStructGetSize($tmpPtr)
	$rawSid = BinaryMid($aCall, $ptrSize + 1, BinaryLen($aCall))
	$mem = DllStructCreate("byte Attributes[" & BinaryLen($rawSid) & "]")
	DllStructSetData($mem, "Attributes", $rawSid)
	$pSid = DllStructGetPtr($mem)
	$bCall = _Security__LookupAccountSid($pSid)
	If IsArray($bCall) Then
		Return "[+] Token Owner  : " & $bCall[1] & "\" & $bCall[0] & @CRLF
	Else
		Return ""
	EndIf
EndFunc   ;==>_GetTokenOwner


;Fixed to handle null pointers/large buffer
Func _GetTokenInformation($hToken, $iClass)
	Local $aCall = DllCall("advapi32.dll", "bool", "GetTokenInformation", "handle", $hToken, "int", $iClass, "struct*", 0, "dword", 0, "dword*", 0)
	If @error Or Not $aCall[5] Or Not $aCall[1] Then Return SetError(@error + 10, @extended, 0)
	Local $iLen = $aCall[5]
	Local $tBuffer = DllStructCreate("byte[" & $iLen & "]")
	$aCall = DllCall("advapi32.dll", "bool", "GetTokenInformation", "handle", $hToken, "int", $iClass, "struct*", $tBuffer, "dword", DllStructGetSize($tBuffer), "dword*", 0)
	If @error Or Not $aCall[0] Then Return SetError(@error, @extended, 0)
	Return $tBuffer
EndFunc   ;==>_GetTokenInformation



Func _GetTokenUser($hToken)
	Local $tmpOut, $aCall, $bCall, $tmpPtr, $ptrSize, $rawSid, $mem, $pSid
	$aCall = DllStructGetData(_GetTokenInformation($hToken, $TOKENUSER), 1)
	$tmpPtr = DllStructCreate("ptr")
	$ptrSize = DllStructGetSize($tmpPtr)
	$rawSid = BinaryMid($aCall, $ptrSize * 2 + 1, BinaryLen($aCall))
	$mem = DllStructCreate("byte Attributes[" & BinaryLen($rawSid) & "]")
	DllStructSetData($mem, "Attributes", $rawSid)
	$pSid = DllStructGetPtr($mem)
	$bCall = _Security__LookupAccountSid($pSid)
	If IsArray($bCall) Then
		$tmpOut = "[+] Token User   : "
		If $bCall[1] Then $tmpOut &= $bCall[1] & "\"
		$tmpOut &= $bCall[0] & @CRLF
	Else
		Return ""
	EndIf
	Return $tmpOut
EndFunc   ;==>_GetTokenUser



Func _LookupPrivilegeName($luid)
	Local $aCall = DllCall("advapi32.dll", "int", "LookupPrivilegeNameW", "ptr", 0, "int*", $luid, "ptr", 0, "dword*", Null)
	$nameLen = Int($aCall[4])
	$nameBuffer = DllStructCreate("wchar[" & $nameLen & "]")
	$aCall = DllCall("advapi32.dll", "int", "LookupPrivilegeNameW", "ptr", 0, "int*", $luid, "ptr", DllStructGetPtr($nameBuffer), "dword*", $nameLen)
	Return DllStructGetData($nameBuffer, 1)
EndFunc   ;==>_LookupPrivilegeName



Func _GetTokenUserSid($hToken)
	Return _GetTokenPSid($hToken, $TOKENUSER)
EndFunc   ;==>_GetTokenUserSid



Func _GetTokenPrivilegeInfo($hToken)
	$d = DllStructGetData(_GetTokenInformation($hToken, $TOKENPRIVILEGES), 1)
	$privCount = Int(BinaryMid($d, 1, 4))
	$offset = 0
	$attribmean = Null
	If Not $privCount Then Return ""
	$tempOut = "[+] Token has following "&$privCount&" privileges" & @CRLF
	For $i = 1 To $privCount
		If $offset == 0 Then $offset = 5
		$luidandattributes = BinaryMid($d, $offset, 12)
		$luid = BinaryMid($luidandattributes, 1, 8)
		$attributes = BinaryMid($luidandattributes, 9, 4)
		Switch $attributes
			Case $SE_PRIVILEGE_DEFAULT_ENABLED
				$attribmean = "Default Enabled"
			Case $SE_PRIVILEGE_DEFAULT
				$attribmean = "Default"
			Case $SE_PRIVILEGE_ENABLED
				$attribmean = "Enabled"
			Case $SE_PRIVILEGE_REMOVED
				$attribmean = "Removed"
			Case $SE_PRIVILEGE_USED_FOR_ACCESS
				$attribmean = "UsedForAccess"
			Case $SE_PRIVILEGE_DISABLED
				$attribmean = "Disabled"
		EndSwitch
		$tempOut &= "    " & "[*] " & _LookupPrivilegeName($luid) & " [" & $attribmean & "]" & @CRLF
		$offset += 12
	Next
	Return $tempOut
EndFunc   ;==>_GetTokenPrivilegeInfo



Func _ProcessTokenInfo($pid)
	Local $tmpOut
	$hProcess = _WinAPI_OpenProcess($TOKEN_MAXIMUM_ALLOWED, 0, $pid)
	If Not $hProcess Then
		$tmpOut &= "[!] Protected    : True" & @CRLF
		$protectedCount += 1
		$protectedPids &= $pid & " ,"
		$hProcess = _WinAPI_OpenProcess($PROCESS_QUERY_LIMITED_INFORMATION, 0, $pid)
	EndIf
	$hToken = _Security__OpenProcessToken($hProcess, $TOKEN_QUERY)
	$tmpOut &= _GetProcessChilds($pid)
	$tmpOut &= _GetProcessType($hProcess)
	$tmpOut &= _GetProcessPath($hProcess)
	$tmpOut &= _GetTokenPrivilegeInfo($hToken)
	$tmpOut &= _GetTokenUser($hToken)
	$tmpOut &=_GetTokenElevation($hToken)
	$tmpOut &= _GetTokenPrimaryGroup($hToken)
	$tmpOut &= _GetTokenType($hToken)
	$tmpOut &= _GetTokenImpersonationLevel($hToken)
	$tmpOut &= _GetTokenOwner($hToken)
	$tmpOut &= _GetTokenGroups($hToken)
	$tmpOut &= _GetTokenDefaultDacl($hToken)
	_WinAPI_CloseHandle($hProcess)
	_WinAPI_CloseHandle($hToken)
	Return $tmpOut
EndFunc   ;==>_ProcessTokenInfo



Func _SelfSePrivilegeCheck()
	$seDebug = _Security__LookupPrivilegeValue(Null, $SE_DEBUG_NAME)
	If $seDebug Then
		ConsoleWrite(@CRLF & "[+] SeDebugPrivilege Available" & @CRLF)
		ConsoleWrite("[+] Getting PID:" & @AutoItPID & " token" & @CRLF)
		$hToken = _Security__OpenProcessToken(_WinAPI_GetCurrentProcess(), $TOKEN_ALL_ACCESS)
		If $hToken Then
			ConsoleWrite("[+] Trying to set SeDebugPrivilege" & @CRLF)
			_Security__SetPrivilege($hToken, $SE_DEBUG_NAME, True)
			ConsoleWrite("[+] Confirming SeDebugPrivilege" & @CRLF)
			$d = DllStructGetData(_GetTokenInformation($hToken, $TOKENPRIVILEGES), 1)
			$privCount = Int(BinaryMid($d, 1, 4))
			$offset = 0
			$seDebugSet = False
			For $i = 1 To $privCount
				If $offset == 0 Then $offset = 5
				$luidandattributes = BinaryMid($d, $offset, 12)
				$highpart = Int(BinaryMid($luidandattributes, 1, 4))
				$luid = BinaryMid($luidandattributes, 1, 8)
				$offset += 12
				If $highpart == $seDebug Then
					$seDebugSet = True
					ExitLoop
				EndIf
			Next
		EndIf
		If $seDebugSet Then
			ConsoleWrite("[+] SeDebugPrivilege Confirmed!" & @CRLF)
		Else
			ConsoleWrite("[-] Set SeDebugPrivilege Failed! Try running as Administrator" & @CRLF)
		EndIf
	Else
		ConsoleWrite(@CRLF & "[+] SeDebugPrivilege Not Available" & @CRLF)
	EndIf
	_WinAPI_CloseHandle($hToken)
	Return $seDebugSet
EndFunc   ;==>_SelfSePrivilegeCheck



Func _WTSEnumerateProcessesEx()
	Local $aCall, $aMem, $level
	$WTS_PROCESS_INFO_STRUCT = "DWORD SessionId; DWORD ProcessId; PTR pProcessName; PTR pUserSid; DWORD NumberOfThreads; DWORD HandleCount;" & _
			"DWORD PagefileUsage; DWORD PeakPagefileUsage; DWORD WorkingSetSize; DWORD PeakWorkingSetSize; INT64 UserTime; INT64 KernelTime;"
	$aCall = DllCall("wtsapi32.dll", "int", "WTSEnumerateProcessesExW", "hwnd", $WTS_CURRENT_SERVER_HANDLE, "dword*", $WTS_PROCESS_INFO_EX, "dword", $WTS_ANY_SESSION, "ptr*", 0, "dword*", 0)

	$aMem = DllStructCreate($WTS_PROCESS_INFO_STRUCT, $aCall[4])
	$totalProcess = $aCall[5]
	For $i = 0 To $aCall[5] - 1
		ConsoleWrite("------------------------------------------------------------------" & @CRLF)
		$aMem = DllStructCreate($WTS_PROCESS_INFO_STRUCT, $aCall[4] + ($i * DllStructGetSize($aMem)))
		$ppid = _WinAPI_GetParentProcess(DllStructGetData($aMem, "ProcessId"))
		$processName = DllStructCreate("wchar[256]", DllStructGetData($aMem, "pProcessName"))
		$output &= "[+] Process Name : " & DllStructGetData($processName, 1) & @CRLF
		$output &= "[+] Process ID   : " & DllStructGetData($aMem, "ProcessId") & @CRLF
		$output &= "[+] Parent ID    : " & $ppid & " -> " & _ProcessGetName($ppid) & @CRLF
		$output &= "[+] Session ID   : " & DllStructGetData($aMem, "SessionId") & @CRLF
		$userSid = _Security__LookupAccountSid(DllStructGetData($aMem, "pUserSid"))
		If IsArray($userSid) Then
			$output &= "[+] Account      : " & $userSid[1] & "\" & $userSid[0] & @CRLF
		Else
			$output &= "[-] Account      : " & @CRLF
		EndIf
		$output &= "[+] User SID     : " & _Security__SidToStringSid(DllStructGetData($aMem, "pUserSid")) & @CRLF
		$output &= "[+] Threads      : " & DllStructGetData($aMem, "NumberOfThreads") & @CRLF
		$output &= _ProcessTokenInfo(DllStructGetData($aMem, "ProcessId"))
		ConsoleWrite($output)
		$output = ""
	Next
	DllCall("wtsapi32.dll", "int", "WTSFreeMemoryEx", "int", 1, "ptr", $aCall[4], "int", $aCall[5])
EndFunc   ;==>_WTSEnumerateProcessesEx


_SelfSePrivilegeCheck()
;ConsoleWrite(_ProcessTokenInfo(832))
_WTSEnumerateProcessesEx()
;ConsoleWrite(@CRLF & "Total Process : " & $totalProcess & @CRLF & "Protected Process : " & $protectedCount & @CRLF)
