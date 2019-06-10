import datetime
import os
import re
import socket
import select
import struct
import sys
import tarfile

class BOOTP:
    MAX_PACKET = 1522
    BOOTP_PORT = 67
    BOOTP_REQUEST = 1
    BOOTP_REPLY = 2

    def __init__(self, address):
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, self.BOOTP_PORT))

    def process(self):
        (request, address) = self.socket.recvfrom(self.MAX_PACKET)

        # decode the bootp request
        (op, htype, hlen, _, xid, _, ciaddr, _, _, _, chaddr, _, fname, vend) = struct.unpack('!4BLHxx4L16s64s128s64s', request)

        if op == self.BOOTP_REQUEST:
            # create a bootp response
            siaddr = socket.inet_aton(self.address)
            response = struct.pack('!4BLHxx2L4s4s16s64s128s64s',
                self.BOOTP_REPLY, htype, hlen, 0, # op, htype, hlen, hops
                xid, 0, # xid, secs
                ciaddr, ciaddr, # ciaddr, yiaddr
                siaddr, siaddr, # siaddr, giaddr
                chaddr, socket.gethostname(), fname, vend) # chaddr, sname, file, vend
            
            print 'bootp: address {} assigned to {:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}'.format(
                address[0], ord(chaddr[0]), ord(chaddr[1]), ord(chaddr[2]), ord(chaddr[3]), ord(chaddr[4]), ord(chaddr[5]))

            self.socket.sendto(response, address)

class TFTP:
    MAX_PACKET = 1522
    TFTP_PORT = 69
    TFTP_BLOCK = 512
    TFTP_RRQ = 1
    TFTP_WRQ = 2
    TFTP_DATA = 3
    TFTP_ACK = 4
    TFTP_ERROR = 5

    def __init__(self, address):
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, self.TFTP_PORT))

    def process(self):
        (request, address) = self.socket.recvfrom(self.MAX_PACKET)

        # decode the tftp request
        op = struct.unpack_from('!H', request)[0]

        if op == self.TFTP_RRQ:
            # decode the request
            params = request[2:].split('\0')
            print 'tftp: rrq file {} mode {}'.format(params[0], params[1])

            # open the file and read the data
            with tarfile.open('riscos_4.52_netinstall.tar', 'r') as netinstall:
                with netinstall.extractfile('tftpboot/' + params[0]) as f:
                    self.data = f.read()

                    # dynamically patch sash binary to use .255 broadcast address
                    if os.path.basename(params[0]) == 'sash.2030':
                        self.data = self.data[:0x15d90] + '\x24\x06\xff\xff' + self.data[0x15d94:]
                    elif os.path.basename(params[0]) == 'sash.std':
                        self.data = self.data[:0x293e4] + '\x24\x06\xff\xff' + self.data[0x293e8:]

            # send the first block
            response = struct.pack('!2H', self.TFTP_DATA, 1) + self.data[0:self.TFTP_BLOCK]
            self.socket.sendto(response, address)
        elif op == self.TFTP_ACK:
            # decode the request
            number = struct.unpack_from('!xxH', request)[0]

            # only respond if there's more data
            if self.data is not None:
                # get next block
                block = self.data[number * self.TFTP_BLOCK:number * self.TFTP_BLOCK + self.TFTP_BLOCK]

                # send the block
                response = struct.pack('!2H', self.TFTP_DATA, number + 1) + block
                self.socket.sendto(response, address)

                # check for final block
                if len(block) < self.TFTP_BLOCK:
                    self.data = None
        elif op == self.TFTP_ERROR:
            # decode the error
            number = struct.unpack_from('!xxH', request)[0]

            if number in range(0, 8):
                print 'tftp: error {} \'{}\''.format(number, [
                    'Not defined, see error message (if any).', 
                    'File not found.', 
                    'Access violation.', 
                    'Disk full or allocation exceeded.',
                    'Illegal TFTP operation.', 
                    'Unknown transfer ID.', 
                    'File already exists.', 
                    'No such user.'][number])

            self.data = None
        else:
            # send error
            response = struct.pack('!2H24s', self.TFTP_ERROR, 4, 'Illegal TFTP operation.')
            self.socket.sendto(response, address)

class BFS:
    MAX_PACKET = 1522
    BFS_PORT = 2201

    def __init__(self, address):
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, self.BFS_PORT))

    def process(self):
        (request, address) = self.socket.recvfrom(self.MAX_PACKET)

        # 32 bytes in this part
        (bfs_rev, bfs_type, bfs_pathlen, bfs_datalen, _, bfs_offset, bfs_flags, bfs_server) = struct.unpack('!2B3H2L16s', request[0:32])

        print 'bfs: address {} received {} bytes type {} offset {} datalen {}'.format(address[0], len(request), bfs_type, bfs_offset, bfs_datalen)

        if bfs_type == 1:
            # enquire
            bfs_filename = request[32:32 + bfs_pathlen - 1]
            
            print 'bfs: type {} filename {}'.format(bfs_type, bfs_filename)

            # open the file and read the data
            with tarfile.open('riscos_4.52_netinstall.tar', 'r') as netinstall:
                with netinstall.extractfile('tftpboot/' + bfs_filename) as f:
                    self.data = f.read()

                    # dynamically patch sash binary to use .255 broadcast address
                    if os.path.basename(bfs_filename) == 'sash.2030':
                        self.data = self.data[:0x15d90] + '\x24\x06\xff\xff' + self.data[0x15d94:]
                    elif os.path.basename(bfs_filename) == 'sash.std':
                        self.data = self.data[:0x293e4] + '\x24\x06\xff\xff' + self.data[0x293e8:]

            # send enquiry response
            response = struct.pack('!2B3H2L16s', bfs_rev, 2, len(bfs_filename) + 1, 0, 0, 0, 0, socket.gethostname()) + bfs_filename + '\0'
            self.socket.sendto(response, address)

            self.last_offset = -1
        elif bfs_type == 3:
            # read data

            if bfs_offset != self.last_offset:
                bfs_filename = request[32:32 + bfs_pathlen]
                data = self.data[bfs_offset:bfs_offset + bfs_datalen]

                response = struct.pack('!2B3H2L16s', bfs_rev, 4, bfs_pathlen, len(data), 0, bfs_offset, 0, socket.gethostname()) + bfs_filename + data
                self.socket.sendto(response, address)

                self.last_offset = bfs_offset
            else:
                self.last_offset = -1

class RSH:
    """
    This class implements a very minimalistic BSD rsh service. A limited
    subset of commands necessary to support RISC/os network installation
    are handled, and no authentication is performed.

    The commands supported are:
      cat
      cd
      date
      grep
      tar
    """
    MAX_PACKET = 4096
    RSH_PORT = 514

    def __init__(self, address):
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((address, self.RSH_PORT))
        self.socket.listen(0)
        self.stderr_server_port = 1023
        self.netinstall = tarfile.open('riscos_4.52_netinstall.tar', 'r')

    def process(self):
        (stdio_socket, address) = self.socket.accept()

        # receive the connection packet
        connect = stdio_socket.recv(self.MAX_PACKET)
        if len(connect) > 1:
            stderr_port = int(connect.split('\0')[0])
            print 'rsh: stdio {} stderr {}'.format(address[1], stderr_port)

            if stderr_port > 0:
                stderr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                stderr_socket.bind((self.address, self.stderr_server_port))
                stderr_socket.connect((address[0], stderr_port))
                self.stderr_server_port -= 1
                if self.stderr_server_port < 512:
                    self.stderr_server_port = 1023
        else:
            print 'rsh: stdio {}'.format(address[1])

        # accept the connection
        stdio_socket.send('\0')

        # receive the first command packet
        request = stdio_socket.recv(self.MAX_PACKET)
        while len(request) > 0:
            # receive additional command packets until we have 3 null-terminated strings
            while request.count('\0') != 3:
                request += stdio_socket.recv(self.MAX_PACKET)

            # decode the command packet
            (luser, ruser, commands, _) = request.split('\0')
            print 'rsh: luser {} ruser {} commands \"{}\"'.format(luser, ruser, commands)

            output = ''
            curdir = ''
            for command in commands.split(';'):
                args = command.split()
                if args[0] == 'cat':
                    try:
                        f = self.netinstall.extractfile('tftpboot' + curdir + args[1])
                        output = f.read()
                        f.close()
                    except:
                        print 'cat: {} does not exist'.format(args[1])
                elif args[0] == 'cd':
                    curdir = args[1] + '/'
                elif args[0] == 'date':
                    output = datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')
                elif args[0] == 'grep':
                    try:
                        f = self.netinstall.extractfile('tftpboot' + curdir + args[2])
                        for line in f.readlines():
                            if re.match(args[1], line):
                                output += line
                        f.close()
                    except:
                        print 'grep: {} does not exist'.format(args[2])
                elif args[0] == 'tar' and args[1] == 'cf' and args[2] == '-':
                    with open('tar.tar', 'w+b') as f:
                        with tarfile.open(mode='w', fileobj=f) as dst:

                            # add parent directories
                            for directory in set([os.path.dirname(x) for x in args[3:-2]]):
                                if len(directory) > 0:
                                    o_tinfo = self.netinstall.getmember('tftpboot' + curdir + directory)
                                    n_tinfo = tarfile.TarInfo.frombuf(o_tinfo.tobuf())
                                    n_tinfo.name = directory
                                    dst.addfile(n_tinfo)

                            # add files
                            for filename in args[3:-2]:
                                o_tinfo = self.netinstall.getmember('tftpboot' + curdir + filename)
                                n_tinfo = tarfile.TarInfo.frombuf(o_tinfo.tobuf())
                                n_tinfo.name = filename
                                if o_tinfo.islnk():
                                    n_tinfo.linkname = n_tinfo.linkname[len('tftpboot' + curdir):]
                                    dst.addfile(n_tinfo)
                                else:
                                    fo = self.netinstall.extractfile(o_tinfo)
                                    dst.addfile(n_tinfo, fileobj=fo)
                                    fo.close()

                        f.seek(0)
                        output = f.read()
                else:
                    print 'rsh: unhandled command \"{}\"'.format(args[0])

            stdio_socket.sendall(output + '\0')

            request = stdio_socket.recv(self.MAX_PACKET)

        print 'rsh: disconnect'

class MIPSBootServer:
    def __init__(self, address):
        self.address = address
        self.daemons = {}

    def register(self, daemon_classes):
        for daemon_class in daemon_classes:
            daemon = daemon_class(self.address)
            self.daemons[daemon.socket] = daemon
        
    def run(self):
        while True:
            (readable, writable, exception) = select.select(self.daemons.keys(), [], [])

            for readable_socket in readable:
                self.daemons[readable_socket].process()

# check usage
if len(sys.argv) == 2:
    mipsboot = MIPSBootServer(sys.argv[1])

    mipsboot.register([BOOTP, TFTP, BFS, RSH])

    mipsboot.run()
else:
    sys.exit('Usage: {} address'.format(sys.argv[0]))
