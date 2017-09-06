# ghetto helper class for ctf style rop challenges
# https://offensivepentest.com/2017/09/06/ropemporium-write4-writeup/

import socket, time, struct, binascii
import telnetlib


class Target():
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

  def __init__(self, ip=None, port=None, length=0xFFFF):
    if not ip or not port:
      return
    print
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.connect((ip, port))
    self.length = length
    self.rop = None
    self.receive = None
    self.log('Connected to target')
    self.line = False

  def send(self, payload=None):
    if not payload and self.rop:
      payload = self.rop
    if self.line:
      payload += '\n'
      self.line = False
    self.socket.send(payload)

  def sendline(self, payload=None):
    self.line = True
    self.send(payload)

  def recv(self, l=None):
    if not l:
      l = self.length
    time.sleep(2)
    self.receive = self.socket.recv(l)
    return self.receive

  def create_rop(self, offset, gadgets):
      p = 'A' * offset
      self.log('Creating ROP Chain','i')
      for gadget in gadgets:
        if isinstance(gadget, (int, long)) and hex(gadget).startswith('0x'):
          p += self.p(gadget)
          print '    ',hex(gadget)
        else:
          p += gadget
          print '    ',gadget
      self.rop = p
      return p

  def recv_until(self, string):
    buff = ''
    while True:
      x = self.socket.recv(1024)
      buff += x
      if x.strip() == string:
        return buff

  def log(self, a, t=None):
    ''''''
    if not t:
      t = self.OKBLUE + '+'
    elif t == 'i':
      t = self.HEADER + '*'
    elif t == 'w':
      t = self.WARNING + '!'
    elif t == 'f':
      t = self.FAIL + '!'
    t  =  self.OKGREEN + '[' + t + self.OKGREEN + ']' + self.ENDC
    print(t + ' %s' % (a))

  def funcs(self, raw):
    raw = raw.strip().split('\n')
    t_dict = {}
    for f in raw:
      f = f.split()
      f_name = f[1].replace('@','_')
      f_addr = f[0]
      t_dict[f_name] = int(f_addr, 16)
      globals()[f_name] = int(f_addr,16)
    self.functions = t_dict
    return self.functions

  
  def p(self, addr):
    '''pack raw packets'''
    return struct.pack('<L', addr)

  def u(self, addr):
    '''unpack raw packets'''
    return struct.unpack('<L', addr)[0]

  def hexdump(self, data=None, bytez=0):
    info_msg = "\t\t------->Hex Dump<-------"
    if not data:
      data = self.recv()
      info_msg = 'Hex Dump for last receive\n'
    self.log(info_msg)
    ndata = binascii.hexlify(data)
    print "Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    ndata = list(self.chunks(ndata[:320],32))
    offset = bytez
    for each in ndata:
      x = ' '.join(each[i:i+2] for i in range(0, len(each), 2))
      printspace = " "*(10-len(hex(offset)))
      print hex(offset) + printspace + x
      offset += 16
    print
    return data

  def chunks(self, l, n):
    n = max(1, n)
    return (l[i:i+n] for i in xrange(0, len(l), n))

  def interactive(self, tty=None):
    telnet = telnetlib.Telnet()
    telnet.sock = self.socket
    self.log('Switching to interactive session\n')
    if tty:
      telnet.write('python -c "import pty;pty.spawn(\'/bin/sh\')"\n')
    telnet.interact()

  def write_payload(self, file_name=None, payload=None):
    if not file_name:
      file_name = 'payload'
    self.log('Writing payload to file : ' + file_name)
    f = open(file_name, 'wb')
    f.write(payload)
    f.close()
