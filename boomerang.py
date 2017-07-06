#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################
#
#           Author: Justin Angra
#           Last Modified: 30 April 2016
#
########################################################

import curses #library for CLI GUI
import time, sys, socket
import select, random, getpass
import tempfile #used to create file for hidden service
from optparse import OptionParser

import stem.connection
from stem.control import Controller
import socks

from threading import Thread

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import base64

# Establish server on local interface
SERVER_IP = '127.0.0.1'
CTRL_PORT = 9051
SOCKS_PORT = 9050
SERVER_PORT = 42761

# Message delays used to prevent server overloading
CLIENT_WAIT=2 #Before client function sends message
SERVER_WAIT=2 #Before server function sends message
NOISE_WAIT=3  #Before sending noise message

# Gui variables
GUI_width=20
chantext=[]
user=[]

commands =[]
min_msg_len=256

STDoutLog=False

count=0
cmdline=""
inspoint=0
pagepoint=0


# Add padding to a message up to min_msg_len
def pad_msg(message):
    if len(message)<min_msg_len:
        message+=chr(0)
        for i in range(min_msg_len-len(message)):
            message+=chr(random.randint(ord('a'),ord('z')))
    return message


## Return unpadded version of input string
def unpad_msg(string):
    out=""
    for c in string:
        if (ord(c)==0): break # char(0) marks start of padding
        if (ord(c)>=0x20) and (ord(c)<0x80):
            out+=c
    return out


# Logs to STDOut or to the chantext channel list
def log(text):
    if (STDOutLog):
        print text
    else:
        maxlen=width-GUI_width-1
        while (True):
            if (len(text[:maxlen])>0):
                chantext.append(text[:maxlen])
            text=text[maxlen:]
            if text=='':
                break
        redraw(stdscr)
        stdscr.refresh()

def chat_quit():
    exit(0)
commands.append(("quit",chat_quit,"Exit the application"))

def changeSize(stdscr):
    global width,height
    size = stdscr.getmaxyx()
    width=size[1]
    height=size[0]

def redraw(stdscr):
    global textpad
    global user
    stdscr.clear()
    # draw Text
    line=height-3
    for i in reversed(range(len(chantext)-pagepoint)):
        try:
            stdscr.addstr(line,0,chantext[i],0)
            if line==0: break
            else: line-=1
        except:
            pass
    # draw user
    for i in range(len(user)):
        buddy=user[i]
        stdscr.addstr(i,width-GUI_width+1,str(buddy),0)
    # draw lines
    stdscr.hline(height-2,0,curses.ACS_HLINE,width)
    stdscr.vline(0,width-GUI_width,curses.ACS_VLINE,height-2)
    # prompt
    prompt="~ "
    stdscr.addstr(height-1,0,"%s%s" % (prompt,cmdline),0)
    stdscr.move(height-1,len(prompt)+inspoint)

# Returns string to send to server
def processLine(command):
    if command.startswith("/"):
        comm=command[1:].split(' ')
        for t in commands:
            if comm[0].startswith(t[0]):
                func=t[1]
                return func(comm)
    return command

class Status():

    # Establish connection to Tor network
    def connect(self, addr = '127.0.0.1', port = 9051):
        self.controller = Controller.from_port(addr, port)

        # Authenticate hidden service to Tor network is required
        try:
            self.controller.authenticate()

        except stem.connection.MissingPassword:
            controller_pass = getpass.getpass("[***] Please enter controller password: ")
            try:
                self.controller.authenticate(controller_pass)
            except stem.connection.PasswordAuthFailed:
                print "[Err] Unable to authenticate, password is incorrect"
                sys.exit(1)

        except stem.connection.AuthenticationFailure as e:
            print "[Err] Unable to authenticate: %s" % e
            sys.exit(1)

        # Collect information on Tor speed, verifying connection
        bytes_read = self.controller.get_info("traffic/read")
        bytes_written = self.controller.get_info("traffic/written")

        print "[***] Tor relay alive. %s bytes read, %s bytes written." % (bytes_read,bytes_written)
        print "[***] Tor version: %s" % str(self.controller.get_version())

        # Set socks port
        try:
            self.socks_port = self.controller.get_conf("SocksPort")
            # Check if controller has a port setup
            if self.socks_port == None:
                sefl.socks_port = 9050
            else:
                self.socks_port = int(self.socks_port)
        except: #failed to pull data from controller
            self.socks_port = 9050
        print "[***] Socks port is: %d" % self.socks_port

        # Establish the hidden service
        print "[***] Establishing hidden service ... "
        hs_dir = tempfile.mkdtemp()
        self.origConfmap = self.controller.get_conf_map("HiddenServiceOptions")
        self.controller.set_options([
                                     ('HiddenServiceDir',hs_dir),
                                     ('HiddenServicePort',"%d %s:%d" % (SERVER_PORT,SERVER_IP,SERVER_PORT))
                                     ])
        self.hostname=open("%s/hostname" % hs_dir,"rb").read().strip()
        print "[***] Hostname is %s" % self.hostname

    # Close connection to Tor network
    def disconnect(self):
        # Remove hidden service
        print "Removing hidden service ..."

    def get_hostname():
        return "%s" % self.hostname

# AES-256
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AES256():
    status = Status()
    key = SHA256.new()
    salt = b'what a cool program!'
    key.update(salt + str(status.get_hostname))

    def encrypt(raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

class Server():
    serverUser={} # Server user dictionary: alias->timestamp
    servermsgs=[] # All msgs to be sent to server
    channelname="" # name of server

    #ƒ Eliminate usernames of all idle users
    def serverUserWipe(self):
        while True:
            time.sleep(10)
            current=time.time()
            waittime = random.randint(60*60*10,60*60*36) # 10 hours to 1.5 days
            for b in self.serverUser:
                if current-self.serverUser[b]>waittime: # Idle for more than the time limit
                    self.serverUser.pop(b) #eliminate username
                    waittime = random.randint(60*60*10,60*60*36)

    # Thread attending to a single client
    def serverThread(self,conn,addr,msg,alias):
        log("(ServerThread): Received connection")
        conn.setblocking(0)
        randomwait=random.randint(1,SERVER_WAIT)
        self.aes = AES256()
        while (True):
            try:
                time.sleep(1)
                ready = select.select([conn], [], [], 1.0)
                if ready[0]:
                    #data = unpad_msg(self.aes.decrypt(str(conn.recv(min_msg_len))))
                    data = unpad_msg(conn.recv(min_msg_len))
                    if len(data)==0: continue
                    message="%s: %s" % (alias,data)
                    # Received PING, send PONG
                    if data.startswith("/PING"):
                        message=""
                        msg.append(data)
                        continue
                    # Change username. Note that we do not add to User before this operation
                    if data.startswith("/alias "):
                        newalias=data[6:].strip()
                        if newalias.startswith("--"):continue
                        log("Alias changed: %s->%s" % (alias,newalias))
                        alias=newalias
                        self.serverUser[newalias]=time.time() # save/refresh timestamp
                        message="Alias changed to %s" % newalias
                        msg.append(message)
                        continue
                    # Return list of all users
                    if data.startswith("/users"):
                        message="Users in %s:" % self.channelname
                        totalbuddies=len(self.servermsgs)
                        for r in self.serverUser:
                            message+=" %s" % r
                            totalbuddies-=1
                        message+=" --anonymous:%d" % totalbuddies
                        msg.append(message)
                        continue
                    if data.startswith("/help"):
                        msg.append("Supported commands:")
                        msg.append("     /help          : Sends this help menu")
                        msg.append("     /users         : Sends the user list")
                        msg.append("     /alias <alias> : Changes the username to <alias>")
                        msg.append("     /quit          : Leaves the chatroom")
                        continue
                    # refresh timestamp
                    self.serverUser[alias]=time.time()
                    # Send 'message' to all queues
                    for m in self.servermsgs:
                        m.append(message)
                # We need to send a message
                if len(msg)>0:
                    randomwait-=1 # Wait some random time to add noise
                    if randomwait==0:
                        m = pad_msg(msg.pop(0))
                        #conn.sendall(self.aes.encrypt(str(m)))
                        conn.sendall(m)
                        randomwait=random.randint(1,SERVER_WAIT)
                # Random wait before sending noise to the client
                if random.randint(0,NOISE_WAIT)==0:
                    ping="/PING "
                    for i in range(120):
                        ping+="%02X" % random.randint(ord('a'),ord('z'))
                    msg.append(ping)
            except:
                self.servermsgs.remove(msg)
                conn.close()
                print "exiting: msgs %d" % len(self.servermsgs)
                raise

    ## Server main thread
    def serverMain(self,channel_name):
        global STDOutLog
        STDOutLog=True
        self.channelname=channel_name
        # Connects to TOR and create hidden service
        self.status=Status()
        self.status.connect(SERVER_IP,CTRL_PORT)
        # Start server socket
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((SERVER_IP,SERVER_PORT))
        log('[***] Server Active')
        log('[***] Connect with the command "%s --connect=%s"' % (sys.argv[0],self.status.hostname))
        s.listen(5)
        # Create server User cleanup thread
        t = Thread(target=self.serverUserWipe, args=())
        t.daemon = True
        t.start()
        while True:
            try:
                conn,addr = s.accept()
                cmsg=[]
                alias="anon_%d" % random.randint(0,10000)
                cmsg.append("Welcome %s, this is %s" % (alias,self.channelname))
                self.servermsgs.append(cmsg)
                t = Thread(target=self.serverThread, args=(conn,addr,cmsg,alias))
                t.daemon = True
                t.start()
            except KeyboardInterrupt:
                self.status.disconnect()
                log("[***] (Main Server Thread): Exiting")
                exit(0)
            except:
                pass


def clientConnection(stdscr,serverURL,msgs):
    global user
    aes = AES256()
    while(True):
        try:
            log("[***] Trying to connect to %s:%d" % (serverURL,SERVER_PORT))
            ## Connects to TOR via Socks
            s=socks.socksocket(socket.AF_INET,socket.SOCK_STREAM)
            s.setproxy(socks.PROXY_TYPE_SOCKS5,SERVER_IP,SOCKS_PORT)
            s.settimeout(100)
            s.connect((serverURL,SERVER_PORT))
            s.setblocking(0)
            log("[***] Connected to %s" % serverURL)
            log("[***] Autorequesting users...")
            msgs.append("/users")
            msgs.append("/help")
            randomwait=random.randint(1,CLIENT_WAIT)
        except:
            log("[Err] Can't connect! retrying...")
            time.sleep(1)
            continue
        try:
            while(True):
                time.sleep(1)
                ready = select.select([s], [], [], 1.0)
                # Received data from server
                if ready[0]:
                    #data=unpad_msg(aes.decrypt(str(s.recv(min_msg_len))))
                    data=unpad_msg(s.recv(min_msg_len))
                    if data.find("/PING ")>-1:
                        continue
                    # Received user list
                    if data.startswith("Users"):
                        user=[]
                        for i in data.split(' ')[1:]:
                            user.append(i)
                    # Write received data to channel
                    log(data)
                # We need to send a message
                if len(msgs)>0:
                    randomwait-=1 # Wait some random time to send noise
                    if randomwait==0:
                        m = pad_msg(msgs.pop(0))
                        #s.sendall(aes.encrypt(str(m)))
                        s.sendall(m)
                        randomwait=random.randint(1,CLIENT_WAIT)
                # send noise in form of PINGs
                if random.randint(0,NOISE_WAIT)==0:
                    ping="/PING "
                    for i in range(120):
                        ping+="%02X" % random.randint(0,255)
                    msgs.append(ping)
        except:
            s.close()
            pass

def clientMain(stdscr,serverURL):
    global cmdline
    global inspoint
    global pagepoint
    global width,height
    changeSize(stdscr)
    redraw(stdscr)

    # Message queue to send to server
    msgs=[]
    t = Thread(target=clientConnection, args=(stdscr,serverURL,msgs))
    t.daemon = True
    t.start()

    # Main Loop
    while True:
        input=stdscr.getch()

        # Event processing
        if (input == curses.KEY_RESIZE):
            changeSize(stdscr)
        # Basic line editor
        if (input == curses.KEY_LEFT) and (inspoint>0):
            inspoint-=1
        if (input == curses.KEY_RIGHT) and (inspoint<len(cmdline)):
            inspoint+=1
        if (input == curses.KEY_BACKSPACE) and (inspoint>0):
            cmdline=cmdline[:inspoint-1]+cmdline[inspoint:]
            inspoint-=1
        if (input == curses.KEY_DC) and (inspoint<len(cmdline)):
            cmdline=cmdline[:inspoint]+cmdline[inspoint+1:]
        if (input == curses.KEY_HOME):
            inspoint=0
        if (input == curses.KEY_END):
            inspoint=len(cmdline)
        # PageUp/PageDown
        if (input == curses.KEY_PPAGE):
            pagepoint+=height-2
            if len(chantext)-pagepoint<0:
                pagepoint=len(chantext)
        if (input == curses.KEY_NPAGE):
            pagepoint-=height-2
            if pagepoint<0: pagepoint=0
        if (input == 10):
            tosend=processLine(cmdline)
            if len(tosend)>0:
                msgs.append(tosend)
            cmdline=""
            inspoint=0

        # Ascii key
        if input>31 and input<128:
            if len(cmdline)<(width-5):
                cmdline=cmdline[:inspoint]+chr(input)+cmdline[inspoint:]
                inspoint+=1
        redraw(stdscr)

def Client(serverURL):
    global stdscr
    global STDOutLog
    STDOutLog=False

    try:
        # Initialize curses lib
        stdscr=curses.initscr()
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(1)
        clientMain(stdscr,serverURL)
        stdscr.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
        exit(0)
    except:
        # In event of error, restore terminal to sane state.
        stdscr.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()


if __name__=='__main__':
    parser = OptionParser()
    parser.add_option("-c", "--connect", action="store", type="string", dest="connect", help="Acts as client, connect to server")
    parser.add_option("-s", "--server", action="store", type="string",dest="channel_name", help="Acts as server")
    if len(sys.argv)==1:
        parser.print_help()
        exit(0)
    (options, args) = parser.parse_args()
    if options.channel_name:
        s=Server()
        s.serverMain(options.channel_name)
    else:
        if len(options.connect)>0:
            Client(options.connect)
        else: parser.print_help()
