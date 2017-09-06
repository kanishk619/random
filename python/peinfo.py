import struct,json
from collections import OrderedDict
from datetime import datetime 
import binascii
from capstone import *

MachineTypes = {"0x0": "AnyMachineType","0x1d3": "Matsushita AM33","0x8664": "AMD64 (x64)","0x1c0": "ARM LE",
        "0x1c4": "ARMv7","0xaa64": "ARMv8 x64","0xebc": "EFIByteCode","0x14c": "Intel x86",
        "0x200": "Intel Itanium","0x9041": "M32R","0x266": "MIPS16","0x366": "MIPS w/FPU",
        "0x466": "MIPS16 w/FPU","0x1f0": "PowerPC LE","0x1f1": "PowerPC w/FP","0x166": "MIPS LE",
        "0x1a2": "Hitachi SH3","0x1a3": "Hitachi SH3 DSP","0x1a6": "Hitachi SH4","0x1a8": "Hitachi SH5",
        "0x1c2": "ARM or Thumb -interworking","0x169": "MIPS little-endian WCE v2"
        }

ArchTypes = {"0x10b":"32","0x20b":"64"}

ImageHeaderSignatures = {"0x10b":"PE32","0x20b":"PE64"}


class PEInfo:
  """
  PEInfo 32/64bit WinPE binary parser class
  Attributes:
    file (str or file object)
  """

  def __init__(self,FILE=None):
    """__init__ method"""
    if isinstance(FILE, file):
      self.binary = FILE
    else:
      if FILE:
        self.binary = file(FILE,"rb")
    self.pInfo = OrderedDict()
    self.FILE = FILE
    self.OFFSET = None
    self.PE_SIG = None


  def __repr__(self):
    self.overview()
    return json.dumps(self.pInfo,indent=4)


  def printOut(self,d=None,g=0):
    """Internal helper method,
    Prints dict or list recursively"""
    if not g:
      d = self.pInfo
    if isinstance(d,list):
      for c in d:
        print '\t'*g+str(c)
    else:
      for k, v in d.iteritems():
        if isinstance(v, dict):
          if g == 0:
            print '\n\n'+'='*20+k+"="*20
          else:
            print '\t'*g+k
          self.printOut(v,g+1)
        else:
          if isinstance(v,list):
            print '\t'*g+k+':'
            self.printOut(v,g+1)
          else:
            diff = 10-len(k)
            print '\t'*g+k+' '*diff+':'+' '*5+str(v)


  def pc(self,xbyte,typez):
    """Internal method to parse characteristics based on binary value
    Arguments:
      xbyte (hex): value to be parsed
      typez (int): list item no from which to parse the binary value
    Returns dict object {binary_value:meaning}
    """
    nlist = []
    xbyte = int(xbyte,16)
    peKeyValue = OrderedDict({0x001:"IMAGE_FILE_RELOCS_STRIPPED",0x002:"IMAGE_FILE_EXECUTABLE_IMAGE",0x004:"IMAGE_FILE_LINE_NUMS_STRIPPED",
      0x008:"IMAGE_FILE_LOCAL_SYMS_STRIPPED",0x010:"IMAGE_FILE_AGGRESIVE_WS_TRIM",0x020:"IMAGE_FILE_LARGE_ADDRESS_AWARE",
      0x080:"IMAGE_FILE_BYTES_REVERSED_LO",0x0100:"IMAGE_FILE_32BIT_MACHINE",0x0200:"IMAGE_FILE_DEBUG_STRIPPED",
      0x0400:"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",0x0800:"IMAGE_FILE_NET_RUN_FROM_SWAP",0x1000:"IMAGE_FILE_SYSTEM",
      0x2000:"IMAGE_FILE_DLL",0x4000:"IMAGE_FILE_UP_SYSTEM_ONLY",0x8000:"IMAGE_FILE_BYTES_REVERSED_HI"})
    subsystemKeyValue = OrderedDict({0x0000:"IMAGE_SUBSYSTEM_UNKNOWN",0x0001:"IMAGE_SUBSYSTEM_NATIVE",0x0002:"IMAGE_SUBSYSTEM_WINDOWS_GUI",
      0x0003:"IMAGE_SUBSYSTEM_WINDOWS_CUI",0x0005:"IMAGE_SUBSYSTEM_OS2_CUI",0x0007:"IMAGE_SUBSYSTEM_POSIX_CUI",
      0x0009:"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",0x0010:"IMAGE_SUBSYSTEM_EFI_APPLICATION",0x0011:"IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
      0x0012:"IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",0x0013:"IMAGE_SUBSYSTEM_EFI_ROM",0x0014:"IMAGE_SUBSYSTEM_XBOX",
      0x0016:"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"})
    dllKeyValue = OrderedDict({0x0001:"Reserved",0x0002:"Reserved",0x0004:"Reserved",0x0008:"Reserved",
      0x0040:"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",0x0080:"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
      0x0100:"IMAGE_DLLCHARACTERISTICS_NX_COMPAT",0x0200:"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
      0x0400:"IMAGE_DLLCHARACTERISTICS_NO_SEH",0x0800:"IMAGE_DLLCHARACTERISTICS_NO_BIND",
      0x1000:"Reserved",0x2000:"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",0x4000:"Reserved",
      0x8000:"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"})
    sectionKeyValue = OrderedDict({0x00000000:"IMAGE_SCN_TYPE_REG",0x00000001:"IMAGE_SCN_TYPE_DSECT",0x00000002:"IMAGE_SCN_TYPE_NOLOAD",
      0x00000004:"IMAGE_SCN_TYPE_GROUP",0x00000008:"IMAGE_SCN_TYPE_NO_PAD",0x00000010:"IMAGE_SCN_TYPE_COPY",
      0x00000020:"IMAGE_SCN_CNT_CODE",0x00000040:"IMAGE_SCN_CNT_INITIALIZED_DATA",0x00000080:"IMAGE_SCN_CNT_UNINITIALIZED_DATA",
      0x00000100:"IMAGE_SCN_LNK_OTHER",0x00000200:"IMAGE_SCN_LNK_INFO",0x00000400:"IMAGE_SCN_TYPE_OVER",
      0x00000800:"IMAGE_SCN_LNK_REMOVE",0x00001000:"IMAGE_SCN_LNK_COMDAT",0x00008000:"IMAGE_SCN_MEM_FARDATA",
      0x00020000:"IMAGE_SCN_MEM_PURGEABLE",0x00040000:"IMAGE_SCN_MEM_LOCKED",0x00080000:"IMAGE_SCN_MEM_PRELOAD",
      0x00100000:"IMAGE_SCN_ALIGN_1BYTES",0x00200000:"IMAGE_SCN_ALIGN_2BYTES",0x00300000:"IMAGE_SCN_ALIGN_4BYTES",
      0x00400000:"IMAGE_SCN_ALIGN_8BYTES",0x00500000:"IMAGE_SCN_ALIGN_16BYTES",0x00600000:"IMAGE_SCN_ALIGN_32BYTES",
      0x00700000:"IMAGE_SCN_ALIGN_64BYTES",0x00800000:"IMAGE_SCN_ALIGN_128BYTES",0x00900000:"IMAGE_SCN_ALIGN_256BYTES",
      0x00A00000:"IMAGE_SCN_ALIGN_512BYTES",0x00B00000:"IMAGE_SCN_ALIGN_1024BYTES",0x00C00000:"IMAGE_SCN_ALIGN_2048BYTES",
      0x00D00000:"IMAGE_SCN_ALIGN_4096BYTES",0x00E00000:"IMAGE_SCN_ALIGN_8192BYTES",0x01000000:"IMAGE_SCN_LNK_NRELOC_OVFL",
      0x02000000:"IMAGE_SCN_MEM_DISCARDABLE",0x04000000:"IMAGE_SCN_MEM_NOT_CACHED",0x08000000:"IMAGE_SCN_MEM_NOT_PAGED",
      0x10000000:"IMAGE_SCN_MEM_SHARED",0x20000000:"IMAGE_SCN_MEM_EXECUTE",0x40000000:"IMAGE_SCN_MEM_READ",
      0x80000000:"IMAGE_SCN_MEM_WRITE"})
    metaflagsKeyValue = OrderedDict({0x00000001:"ILOnly",0x00000002:"Requires32Bit",0x00000004:"ILLibrary",0x00000008:"StrongNameSigned",
      0x00000010:"NativeEntryPoint",0x00010000:"TrackDebugData",0x00020000:"Prefers32Bit"})
    listOfDicts = [peKeyValue,subsystemKeyValue,dllKeyValue,sectionKeyValue,metaflagsKeyValue]
    keyValue = listOfDicts[typez]
    for value, msg in keyValue.iteritems():
      if typez == 1:
        if (xbyte == value):
          nlist.append(msg)
      else:
        if (xbyte & value):
          nlist.append(msg)
    return nlist


  def chta(self,h):
    """converts supplied hex to ascii
    Arguments:
      h (hex)
    Returns converted value
    """
    chars = []
    while h != 0x0:
      chars.append(chr(h & 0xFF))
      h = h >> 8
    return "".join(chars)


  def fo(self,rva):
    """Method to calculate fileoffset from rva
    Arguments:
      rva (int)
    Returns fileoffset
    """
    sections = self.pInfo["Sections"]
    for section in sections:
      va = int(self.pInfo["Sections"][section]["VirtualAddress"]["value"],16)
      ra = int(self.pInfo["Sections"][section]["PointerToRawData"]["value"],16)
      vsize = self.pInfo["Sections"][section]["VirtualSize"]["value"]
      pos = rva - va
      if pos >= 0 and pos < vsize:
        return pos+ra


  def exports(self,search=None,ords=False):
    """Method to parse function exports, works if binary is DLL
    Arguments:
      search (Optional[str]): If supplied, returns VA of supplied function name
      ords (int): Not yet implemented
    Updates self.pInfo with results
    """
    # if not dll
    if not self.PE_TYPE >= 0x2000:
      return
    rva = int(self.pInfo["PE"]["ImageOptionalHeader"]["DirectoryStructures"]["ExportDirectoryRVA"]["value"],16)
    fileOffset = self.fo(rva)
    exports = OrderedDict()
    self.binary.seek(fileOffset)
    exports["Characteristics"] = self.s("<I",True)
    exports["TimeDateStamp"] = {"offset":self.binary.tell(),"bytes":4,
        "value":datetime.fromtimestamp(int(struct.unpack("<I",self.binary.read(4))[0])).strftime("%Y-%m-%d %H:%M:%S")}
    exports["MajorVersion"] = self.s("<H",True)
    exports["MinorVersion"] = self.s("<H",True)
    exports["Name"] = self.s("<I",True)
    exports["Base"] = self.s("<I",True)
    exports["NumberOfFunctions"] = self.s("<I",True)
    exports["NumberOfNames"] = self.s("<I",True)
    exports["AddressOfFunctions"] = self.s("<I",True)
    exports["AddressOfNames"] = self.s("<I",True)
    exports["AddressOfNameOrdinals"] = self.s("<I",True)
    nFuncs = int(exports["NumberOfFunctions"]["value"],16)
    nNames = int(exports["NumberOfNames"]["value"],16)
    exportsDict = OrderedDict()
    # exportsDict can be used as a list in case multiple names with same values causing issues
    nameFileOffset = []
    funcrva = []
    ordDict = {}
    self.binary.seek(self.fo(int(exports["AddressOfFunctions"]["value"],16)))
    #storing all function RVAs
    for x in range(0,nFuncs):
      e = self.s("<I",True)["value"]
      funcrva.append(e)
    #storing all name RVAs
    self.binary.seek(self.fo(int(exports["AddressOfNames"]["value"],16)))
    for y in range(0,nNames):
      rva = self.s("<I",False)["value"]
      fileOffset = self.fo(rva)
      nameFileOffset.append(fileOffset)
    # storing all ordinals
    nOrds = nFuncs - (nFuncs - nNames)
    self.binary.seek(self.fo(int(exports["AddressOfNameOrdinals"]["value"],16)))
    for z in range(0,nOrds): 
      ordinal = self.s("<H",False)["value"]
      ordDict.update({ordinal:hex(nameFileOffset[z])})

    for u in range(len(funcrva)):
      try:
        tempname = ""
        self.binary.seek(int(ordDict[u],16))
        while True:
          byte = self.binary.read(1)
          if byte != "\x00":
            tempname += byte
          else:
            break
        if ords:
          exportsDict.update({tempname:[funcrva[u],hex(u)]})
        else:
          exportsDict.update({tempname:funcrva[u]})
      except KeyError:
        pass

    if search:
      try:
        if ords:
          addr = int(self.pInfo["PE"]["ImageOptionalHeader"]["ImageBase"]["value"],16) + int(exportsDict[search][0],16)
        else:
          addr = int(self.pInfo["PE"]["ImageOptionalHeader"]["ImageBase"]["value"],16) + int(exportsDict[search],16)
        return hex(addr)
      except KeyError:
        return None
    exports["TotalFunctions"] = len(exportsDict)
    exports["Functions"] = exportsDict
    self.binary.seek(self.fo(int(exports["Name"]["value"],16)))
    tempname = ""
    while True:
      x = self.binary.read(1)
      if x == "\x00":
        break
      tempname += x
    exports["Name"]["value"] = {exports["Name"]["value"]:tempname}
    self.pInfo["ExportDirectory"] = exports


  def imports(self,search=None,ords=False):
    """Method to parse function imports
    Arguments:
      search (Optional[str]): function name to search
      ords (int): not yet implemented
    Updates self.pInfo with results
    """
    ds = self.pInfo["PE"]["ImageOptionalHeader"]["DirectoryStructures"]
    rva = int(ds["ImportDirectoryRVA"]["value"],16)
    size = int(ds["ImportDirectorySize"]["value"],16)
    #check whether imports are even done or not
    if not rva and not size:
      return None
    fileOffset = self.fo(rva)
    # end = fileOffset + size
    self.binary.seek(fileOffset)
    n = 0; importDescriptor = []; ssd = OrderedDict(); nulls = 0
    finalImportList = OrderedDict()
    while True:
      rr = ["OriginalFirstThunk","TimeDateStamp","ForwarderChain","NameRVA","FirstThunk"]
      z = self.s("<I",True)["value"]
      ssd.update({rr[n]:z})
      n += 1
      ## below fails in case the ImportDirectorySize is less 
      ## due to which end is less than self.binary.tell()
      # if self.binary.tell() >= end:
      #   ssd.clear()
      #   break
      if n == 5:
        importDescriptor.append(ssd)
        ssd = OrderedDict()
        n = 0
      if z == "0x0":
        nulls += 1
      else:
        nulls = 0
      if nulls == 4:
        break

    for imprt in importDescriptor:
      rva = int(imprt["NameRVA"],16)
      nameOffset = self.fo(rva)
      importName = ""; 
      self.binary.seek(nameOffset)
      while True:
        byte = self.binary.read(1)
        if byte != "\x00": #null check
          importName += byte
        else:
          break
      imprt = OrderedDict({importName:imprt})
      oftarray = []; #array to store offsets
      oftRva = int(imprt[importName]["OriginalFirstThunk"],16)
      oftFo = self.fo(oftRva)
      self.binary.seek(oftFo)
      while True:
        #64bit adjustments
        if self.PE_SIG == "0x20b":
          x = self.s("<Q",True)["value"]
        else:
          x = self.s("<I",True)["value"]
        if x == "0x0":  # chk null terminator
          break
        else:
          if x[:4] != "0x80":  # check if import by oridinal only or not
            cAddr = self.binary.tell()
            xFo = self.fo(int(x,16))
            self.binary.seek(xFo)
            hint = hex(struct.unpack("<H", self.binary.read(2))[0])
            tempname = ""
            while True:
              byte = self.binary.read(1)
              if byte != "\x00":
                tempname += byte
              else:
                break
            self.binary.seek(cAddr)
          else: 
            tempname = "ImportByOrdinal"
            hint = hex(int(x,16))
        oftarray.append([x,hint,tempname])
      y = OrderedDict()
      y["TotalFunctions"] = len(oftarray); y["Functions"] = oftarray
      imprt[importName].update(y)
      finalImportList.update(imprt)
    self.pInfo["ImportDirectory"] = finalImportList
    return finalImportList


  def find_caves(self,size=250):
    """Finds caves in the whole binary
    Arguments:
      size (int): Size of case to be found
    Returns list of caves
    """
    c = 0; i = 0; caves = []
    a = self.binary
    a.seek(0)
    while True:
      byte = a.read(1)
      if byte == "\x00":
        if not c:
          c = a.tell()-1
        i+=1
      if byte != "\x00":
        if i >= size:
          caves.append([c,a.tell()-1])
        c = 0; i=0
      if not byte:
        break
    self.pInfo["Caves"] = OrderedDict()
    self.pInfo["Caves"]["Total"] = len(caves)
    self.pInfo["Caves"]["Inside_Section"] = OrderedDict()
    self.pInfo["Caves"]["Outside_Section"] = []
    for caves in caves:
      for section in self.pInfo["Sections"]:
        sectionFound = False
        sectionSize = self.pInfo["Sections"][section]["SizeOfRawData"]["value"]
        sectionStart = int(self.pInfo["Sections"][section]["PointerToRawData"]["value"],16)
        sectionEnd = sectionStart + sectionSize
        caveLength = caves[1] - caves[0]
        if caves[0] >= sectionStart and caves[1] <= sectionEnd and size <= caveLength:
          data = OrderedDict()
          data["Start"] = hex(caves[0])
          data["End"] = hex(caves[1])
          data["Length"] = caveLength
          try:
            if isinstance(self.pInfo["Caves"]["Inside_Section"][section],list):
              pass
          except KeyError:
            self.pInfo["Caves"]["Inside_Section"][section] = []
          self.pInfo["Caves"]["Inside_Section"][section].append(data)
          sectionFound = True
          break
      if sectionFound is False:
        try:
          data = OrderedDict()
          data["Start"] = hex(caves[0])
          data["End"] = hex(caves[1])
          data["Length"] = caves[1] - caves[0]
          try:
            if isinstance(self.pInfo["Caves"]["Outside_Section"],list):
              pass
          except KeyError:
            self.pInfo["Caves"]["Outside_Section"] = []
          self.pInfo["Caves"]["Outside_Section"].append(data)
        except Exception as e:
          pass


  def s(self,formatt,hexz=None,special=None,arg=None):
    """Struct helper function
    Arguments:
      format (str): byte order and format, ex: <L for little endian 4bytes
      hexz (bool): whether to return hex value or int
      special (dict,list,object): parse from supplied dict, list or function
      arg (args): to be passed to special if function
      o Optional(bool): is called from overview function
    Returns retrieved binary value
    """
    u = {"<B":1,"<H":2,"<I":4,"<L":4,"<Q":8}
    self.OFFSET = hex(self.binary.tell())
    bytez = u[formatt]
    if self.calfunc:
      if hexz:
        return hex(struct.unpack(formatt,self.binary.read(bytez))[0])
      else:
        return struct.unpack(formatt,self.binary.read(bytez))[0]
    if hexz:
      # rstrip coz of windows hex() returns type ,e.g:L (long)
      value = hex(struct.unpack(formatt,self.binary.read(bytez))[0]).rstrip("L")
    else:
      value = struct.unpack(formatt,self.binary.read(bytez))[0]
    if isinstance(special, dict):
      value = special[value]
    elif isinstance(special, list):
      value = special[value]
    elif special:
      if arg: 
        value = special(value,arg)
      else:
        value = special(value)
    return {"value":value,"offset":self.OFFSET,"bytes":bytez}


  def cb(self):
    """
    Check binary and parses info like number of bytes for each item,
    its file offset and value
    Updates self.pInfo
    """
    self.calfunc = False
    self.binary.seek(0)
    x = struct.unpack("<H",self.binary.read(2))[0]
    #check for valid MSDOS header sig
    if hex(x) == "0x5a4d":
      self.pInfo["MSDOS"] = OrderedDict()
      self.binary.seek(0)
      self.pInfo["MSDOS"]["Signature"] = self.s("<H",True)
      self.binary.seek(0+6)
      self.pInfo["MSDOS"]["RelocationTables"] = self.s("<H",False)
      self.pInfo["MSDOS"]["MinAlloc"] = self.s("<H",True)
      self.pInfo["MSDOS"]["MaxAlloc"] = self.s("<H",True)
      self.binary.seek(60)
      self.pInfo["MSDOS"]["e_lfanew"] = self.s("<L",True)
    # collecting DOS STUB info
    self.pInfo["MSDOS_STUB"] = OrderedDict()
    garbage_check = int(self.pInfo["MSDOS"]["e_lfanew"]["value"],16)-self.binary.tell()
    self.pInfo["MSDOS_STUB"] = {"bytes":self.binary.tell(),
                "offset":self.binary.tell(),"value":hex(struct.unpack("<I",self.binary.read(4))[0])}
    # checking whether any garbage data exists in between DOS_STUB and PE_HEADER
    if garbage_check > 64:
      self.pInfo["GARBAGE"] = OrderedDict()
      self.pInfo["GARBAGE"] = {"bytes":garbage_check-64,"value":hex(struct.unpack("<I",self.binary.read(4))[0]),
                              "offset":self.pInfo["MSDOS_STUB"]["offset"]+64}
    # check for valid PE header sig
    self.binary.seek(int(self.pInfo["MSDOS"]["e_lfanew"]["value"],16))
    offset = self.binary.tell()
    x = struct.unpack("<L",self.binary.read(4))[0]
    if hex(x) == "0x4550":
      self.pInfo["PE"] = OrderedDict()
      pe = self.pInfo["PE"]
      pe["Signature"] = {"value":hex(x),"offset":offset,"bytes":4}
      pe["Machine"] = self.s("<H",True,MachineTypes)
      pe["TotalSections"] = self.s("<H",False)
      pe["TimeStamp"] = {"offset":self.binary.tell(),"bytes":4,"value":datetime.fromtimestamp(int(struct.unpack("<L",
                        self.binary.read(4))[0])).strftime("%Y-%m-%d %H:%M:%S")}
      pe["PtrToSymbolTable"] = self.s("<L",True)
      pe["NoOfSymbols"] = self.s("<L",False)
      pe["SizeOfOptionalHeader"] = self.s("<H",True)
      pe["Characteristics"] = OrderedDict()
      pe["Characteristics"] = self.s("<H",True)
      pe["Characteristics"]["value"] = {pe["Characteristics"]["value"]:self.pc(pe["Characteristics"]["value"],0)}
      # updating self type to whether dll image or executable
      self.PE_TYPE = int(pe["Characteristics"]["value"].keys()[0],16)
      pe["ImageOptionalHeader"] = OrderedDict()
      ioh = pe["ImageOptionalHeader"]
      # setting PE_SIG for 64bit adjustments
      self.PE_SIG = self.s("<H",True)["value"]
      ioh["Signature"] = {"offset":self.OFFSET,"value":self.PE_SIG,"bytes":2}
      ioh["Signature"]["value"] = {ioh["Signature"]["value"]:ImageHeaderSignatures[ioh["Signature"]["value"]]}
      ioh["MajorLinkerVersion"] = self.s("<B",True)
      ioh["MinorLinkerVersion"] = self.s("<B",True)
      ioh["SizeOfCode"] = self.s("<I",True)
      ioh["SizeOfInitializedData"] = self.s("<I",True)
      ioh["SizeOfUninitializedData"] = self.s("<I",True)
      ioh["AddressOfEntryPoint"] = self.s("<I",True)
      ioh["BaseOfCode"] = self.s("<I",True)
      #making 64bit adjustments
      if self.PE_SIG == "0x10b":
          ioh["BaseOfData"] = self.s("<I",True)
      if self.PE_SIG == "0x20b":
        formatz = "<Q"
      else:
        formatz = "<I"
      ioh["ImageBase"] = self.s(formatz,True)
      ioh["SectionAlignment"] = self.s("<I",True)
      ioh["FileAlignment"] = self.s("<I",True)
      ioh["MajorOperatingSystemVersion"] = self.s("<H",False)
      ioh["MinorOperatingSystemVersion"] = self.s("<H",False)
      ioh["MajorImageVersion"] = self.s("<H",False)
      ioh["MinorImageVersion"] = self.s("<H",False)
      ioh["MajorSubsystemVersion"] = self.s("<H",False)
      ioh["MinorSubsystemVersion"] = {"offset":self.binary.tell(),"value":struct.unpack("<H",self.binary.read(2))[0]}
      ioh["Win32VersionValue"] = self.s("<I",False)
      ioh["SizeOfImage"] = self.s("<I",True)
      ioh["SizeOfHeaders"] = self.s("<I",True)
      ioh["CheckSum"] = self.s("<I",True)
      ioh["Subsystem"] = self.s("<H",True)
      ioh["Subsystem"]["value"] = {ioh["Subsystem"]["value"]:self.pc(ioh["Subsystem"]["value"],1)}
      dllsig = self.s("<H",True)
      dllsig["value"] = {dllsig["value"]:self.pc(dllsig["value"],2)}
      ioh["DllCharacteristics"] = dllsig
      ioh["SizeOfStackReserve"] = self.s(formatz,True)
      ioh["SizeOfStackCommit"] = self.s(formatz,True)
      ioh["SizeOfHeapReserve"] = self.s(formatz,True)
      ioh["SizeOfHeapCommit"] = self.s(formatz,True)
      ioh["LoaderFlags"] = self.s("<I",True)
      ioh["NumberOfRvaAndSizes"] = self.s("<I",False)
      ioh["DirectoryStructures"] = OrderedDict()
      peStructures = ["ExportDirectoryRVA","ExportDirectorySize","ImportDirectoryRVA","ImportDirectorySize","ResourceDirectoryRVA",
      "ResourceDirectorySize","ExceptionDirectoryRVA","ExceptionDirectorySize","SecurityDirectoryRVA",
      "SecurityDirectorySize","RelocationDirectoryRVA","RelocationDirectorySize","DebugDirectoryRVA","DebugDirectorySize",
      "ArchitechtureDirectoryRVA","ArchitechtureDirectorySize","GlobalPtr","Reserved","TLSDirectoryRVA","TLSDirectorySize",
      "ConfigurationDirectoryRVA","ConfigurationDirectorySize","BoundImportDirectoryRVA","BoundImportDirectorySize",
      "ImportAddressTableDirectoryRVA","ImportAddressTableDirectorySize","DelayImportDirectoryRVA","DelayImportDirectorySizes",
      "CLRRuntimeHeaderRVA","CLRRuntimeHeaderSize","Reserved1","Reserved2"]
      for structure in peStructures:
        offset = self.binary.tell()
        ioh["DirectoryStructures"][structure] = self.s("<I",True)
      #starting section enumeration, use list since dict override incase of same section names
      self.pInfo["Sections"] = OrderedDict()
      sections = int(pe["TotalSections"]["value"])
      for i in range(0,sections):
        # name = self.chta(self.s("<Q",False)["value"])
        name = self.binary.read(8).split("\x00")[0] # more efficient
        data = OrderedDict()
        data_properties = (("VirtualSize","<I",False),("VirtualAddress","<I",True),("SizeOfRawData","<I",False),("PointerToRawData","<I",True),
        ("PointerToRelocations","<I",True),("PointerToLinenumbers","<I",False),("NumberOfRelocations","<H",False),("NumberOfLinenumbers","<H",False))
        for p,s,b in data_properties:
          data[p] = self.s(s,b)
        data["Characteristics"] = OrderedDict()
        t1 = self.s("<I",True)
        t1["value"] = {t1["value"]:self.pc(t1["value"],3)}
        data["Characteristics"] = t1
        # check if section already exists in dict (duplicate names),
        # if exist, append index
        try:
          self.pInfo["Sections"][name] in self.pInfo["Sections"]
        except TypeError:
          self.pInfo["Sections"][name+"_"+str(i)] = data
        except KeyError:
          if name.strip() == "":
            self.pInfo["Sections"][name+"_"+str(i)] = data
          else:
            self.pInfo["Sections"][name] = data

      # updating filealignment with start and end offset along with length of alignment
      fa_start = self.binary.tell()
      fa_end = int(ioh["FileAlignment"]["value"],16)
      fa_length = fa_end-fa_start
      self.binary.seek(fa_end)
      t1 = int(ioh["DirectoryStructures"]["CLRRuntimeHeaderRVA"]["value"],16)
      t2 = int(ioh["SectionAlignment"]["value"],16) 
      padded_offset =  t1 % t2 + self.binary.tell() #jump to CLR info offset
      if t1:
        self.binary.seek(padded_offset)
        self.pInfo["IMPORT_TABLES"] = OrderedDict()
        import_tables_properties = (("CLRHeaderSize","<I",True),("MajorRuntimeVersion","<H",True),("MinorRuntimeVersion","<H",True),
        ("MetadataRVA","<I",True),("MetadataSize","<I",False),("Flags","<I",True),("EntryPointToken","<I",True))
        for p,s,b in import_tables_properties:
          self.pInfo["IMPORT_TABLES"][p] = self.s(s,b)
        self.pInfo["IMPORT_TABLES"]["Flags"] = self.pc(self.pInfo["IMPORT_TABLES"]["Flags"]["value"],4)
    return "Valid %s binary found" % (ImageHeaderSignatures[str(self.PE_SIG)])


  def overview(self):
    """
    Lazy method to give basic overview of supplied binary
    Updates self.pInfo
    """
    self.calfunc = True
    self.pInfo.clear()
    self.binary.seek(0)
    x = self.s("<H",False)
    #check for valid MSDOS header sig
    if hex(x) == "0x5a4d":
      self.pInfo['MSDOS'] = OrderedDict()
      self.binary.seek(0)
      self.pInfo['MSDOS']['Signature'] = self.s("<H",True)
      self.binary.seek(0+6)
      self.pInfo['MSDOS']['RelocationTables'] = self.s("<H",False)
      self.pInfo['MSDOS']['MinAlloc'] = self.s("<H",True)
      self.pInfo['MSDOS']['MaxAlloc'] = self.s("<H",True)
      self.binary.seek(60)
      self.pInfo['MSDOS']['e_lfanew'] = self.s("<L",True)

    # check for valid PE header sig
    self.binary.seek(int(self.pInfo['MSDOS']['e_lfanew'],16))
    x = struct.unpack("<L",self.binary.read(4))[0]
    if hex(x) == "0x4550":
      self.pInfo['PE'] = OrderedDict()
      pe = self.pInfo['PE']
      pe['Signature'] = hex(x)
      pe['Machine'] = MachineTypes[self.s("<H",True)]
      pe['TotalSections'] = self.s("<H",False)
      pe['TimeStamp'] = datetime.fromtimestamp(self.s("<L",False)).strftime('%Y-%m-%d %H:%M:%S')
      pe['PtrToSymbolTable'] = self.s("<L",True)
      pe['NoOfSymbols'] = self.s("<L",False)
      pe['SizeOfOptionalHeader'] = self.s("<H",False)
      pe['Characteristics'] = OrderedDict()
      pe['Characteristics'] = self.s("<H",True)
      pe['Characteristics']['Flags'] = self.pc(pe['Characteristics'],0)
      pe['ImageOptionalHeader'] = OrderedDict()
      ioh = pe['ImageOptionalHeader']
      self.PE_SIG = self.s("<H",True)
      ioh['Signature'] = ImageHeaderSignatures[self.PE_SIG]
      ioh['MajorLinkerVersion'] = self.s("<B",True)
      ioh['MinorLinkerVersion'] = self.s("<B",True)
      ioh['SizeOfCode'] = self.s("<I",False)
      ioh['SizeOfInitializedData'] = self.s("<I",False)
      ioh['SizeOfUninitializedData'] = self.s("<I",False)
      ioh['AddressOfEntryPoint'] = self.s("<I",True)
      ioh['BaseOfCode'] = self.s("<I",True)
      #making 64bit adjustments
      if self.PE_SIG == "0x10b":
        ioh['BaseOfData'] = self.s("<I",True)
      if self.PE_SIG == "0x20b":
        bytez = 8; formatz = "<Q"
      else:
        bytez = 4; formatz = "<I"
      ioh_properties = (("ImageBase",formatz,True), ("SectionAlignment","<I",True), ("FileAlignment","<I",True), ("MajorOperatingSystemVersion","<H",False), 
      ("MinorOperatingSystemVersion","<H",False), ("MajorImageVersion","<H",False), ("MinorImageVersion","<H",False), ("MajorSubsystemVersion","<H",False), 
      ("MinorSubsystemVersion","<H",False), ("Win32VersionValue","<I",False), ("SizeOfImage","<I",True), ("SizeOfHeaders","<I",True), ("CheckSum","<I",True), 
      ("Subsystem","<H",True), ("DllCharacteristics","<H",True), ("SizeOfStackReserve",formatz,True), ("SizeOfStackCommit",formatz,True), 
      ("SizeOfHeapReserve",formatz,True), ("SizeOfHeapCommit",formatz,True), ("LoaderFlags","<I",True), ("NumberOfRvaAndSizes","<I",False))
      for p,s,b in ioh_properties:
        ioh[p] = self.s(s,b)
      ioh['DirectoryStructures'] = OrderedDict()
      ds = ioh['DirectoryStructures']
      ds_properties = (("ExportDirectoryRVA","<I",True),("ExportDirectorySize","<I",True),("ImportDirectoryRVA","<I",True),("ImportDirectorySize","<I",True),
      ("ResourceDirectoryRVA","<I",True),("ResourceDirectorySize","<I",True),("ExceptionDirectoryRVA","<I",True),("ExceptionDirectorySize","<I",True),
      ("SecurityDirectoryRVA","<I",True),("SecurityDirectorySize","<I",True),("RelocationDirectoryRVA","<I",True),("RelocationDirectorySize","<I",True),
      ("DebugDirectoryRVA","<I",True),("DebugDirectorySize","<I",True),("ArchitechtureDirectoryRVA","<I",True),("ArchitechtureDirectorySize","<I",True),
      ("GlobalPtr","<I",True),("Reserved","<I",True),("TLSDirectoryRVA","<I",True),("TLSDirectorySize","<I",True),("ConfigurationDirectoryRVA","<I",True),
      ("ConfigurationDirectorySize","<I",True),("BoundImportDirectoryRVA","<I",True),("BoundImportDirectorySize","<I",True),
      ("ImportAddressTableDirectoryRVA","<I",True),("ImportAddressTableDirectorySize","<I",True),("DelayImportDirectoryRVA","<I",True),
      ("DelayImportDirectorySizes","<I",True),("CLRRuntimeHeaderRVA","<I",True),("CLRRuntimeHeaderSize","<I",True),("Reserved1","<I",True),
      ("Reserved2","<I",True))
      for p,s,b in ds_properties:
        ds[p] = self.s(s,b)
      self.pInfo['Sections'] = OrderedDict()
      #starting section enumeration
      sections = int(pe['TotalSections'])
      for i in range(0,sections):
        name = self.chta(self.s("<Q",False))
        # name = self.binary.read(8).split("\x00")[0]    #more efficient
        data = OrderedDict()
        data['VirtualSize'] = self.s("<I",True)
        data['VirtualAddress'] = self.s("<I",True)
        data['SizeOfRawData'] = self.s("<I",True)
        data['PointerToRawData'] = self.s("<I",True)
        data['PointerToRelocations'] = self.s("<I",True)
        data['PointerToLinenumbers'] = self.s("<I",True)
        data['NumberOfRelocations'] = self.s("<H",False)
        data['NumberOfLinenumbers'] = self.s("<H",False)
        data['Characteristics'] = self.s("<I",True)
        try:
          self.pInfo["Sections"][name] in self.pInfo["Sections"]
        except TypeError:
          self.pInfo["Sections"][name+"_"+str(i)] = data
        except KeyError:
          self.pInfo["Sections"][name] = data


  def psh(self, string):
    """Helper method for hexdump, returns string to hex"""
    for c in string:
      return "0x%02x " % (c)


  def df(self,section=None,startOffset=None,endOffset=None,length=None,mode=str(None),inline=None):
    """Disassembles file"""
    file = self.binary
    if endOffset:
      length = int(endOffset) - int(startOffset)
    if section and len(section) >= 1:
      startOffset = int(self.pInfo["Sections"][section]["PointerToRawData"]["value"],16)
    if self.pInfo:
      mode = int(ArchTypes[self.PE_SIG])
      if not length:
        length = 200

    bytez = int(length)
    seek = int(startOffset)

    with file as f:
        if seek:
          f.seek(seek)
        buffer = f.read(bytez)

    buffer = binascii.hexlify(buffer)
    if inline:
      print buffer[:200]
      return
    if section:
      hexDump(buffer,bytez=seek)
    else:
      hexDump(buffer)
    ds(shellcode=buffer,mode=str(mode))


def ds(shellcode=None,mode=None):
  """Disassembles supplied binary shellcode"""
  CODE = shellcode.replace(' ','').replace('\\x', '').decode('hex')
  print '\t\t------>Disassembly<------\n'
  ARCH = {'x86':CS_ARCH_X86}
  MODE = {'16':CS_MODE_16, '32':CS_MODE_32, '64':CS_MODE_64}
  md = Cs(ARCH["x86"], MODE[mode])
  ss = md.disasm(CODE, 1)
  md.detail = True
  for i in ss:
    a = ""
    for z in i.opcode:
      if hex(z) != "0x0":
        a += hex(z).replace('0x','')
    print '0x%x:\t%s      \t%s %s' % (i.address, a+hex(i.modrm).replace('0x','').replace('0',''),i.mnemonic, i.op_str)
    a=""


def chunks(l,n):
  n = max(1, n)
  return (l[i:i+n] for i in xrange(0, len(l), n))


def hexDump(data,bytez=0,section=None):
  print;print "\t\t------->Hex Dump<-------";print
  print "Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
  data = list(chunks(data[:320],32))
  offset = bytez
  for each in data:
    x = ' '.join(each[i:i+2] for i in range(0, len(each), 2))
    printspace = " "*(10-len(hex(offset)))
    print hex(offset) + printspace + x
    offset += 16
  print
