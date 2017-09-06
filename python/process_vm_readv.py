from ctypes import *
import sys

def chunks(l,n):
    n = max(1, n)
    return (l[i:i+n] for i in xrange(0, len(l), n))

def hexDump(addr,data):
    print "-"*26+"Hex Dump"+"-"*25
    print "Offset(h)   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    data = list(chunks(data,32))
    offset = addr
    hoffset = hex(offset).rstrip('L')
    printspace = " " * (12-len(hoffset))
    for each in data:
        x = ' '.join(each[i:i+2] for i in range(0, len(each), 2))
        print hex(offset).rstrip('L') + printspace + x
        offset += 16
    print

def process_vm_readv(pid,addr,buflen):
    class iovec(Structure):
        _fields_ = [("iov_base",c_void_p),("iov_len",c_size_t)]

    local = (iovec*2)()
    remote =  (iovec*1)()[0]
    buf = (c_char*buflen)()

    local[0].iov_base = cast(byref(buf),c_void_p)
    local[0].iov_len = buflen
    remote.iov_base = c_void_p(addr)
    remote.iov_len = buflen

    libc = CDLL("libc.so.6")
    vm = libc.process_vm_readv
    vm.argtypes = [c_int, POINTER(iovec), c_ulong, POINTER(iovec), c_ulong, c_ulong]

    nread = vm(pid,local,2,remote,1,0)
    if nread != -1:
        return (nread,buf)

def main():
    try:
        pid = int(sys.argv[1])
        addr = int(sys.argv[2],16)
        buflen = int(sys.argv[3])
    except IndexError:
        print "\nUsage process_vm_readv.py pid address bytes\n"
        exit(0)
    print "\n[+] Reading %s bytes from pid:%s at address:%s\n" %(buflen,pid,hex(addr).rstrip('L'))
    bytes = ""
    for i in process_vm_readv(pid,addr,buflen)[1]: bytes += "%02x" % (ord(i))
    hexDump(addr,bytes)

if __name__ == '__main__':
    main()
