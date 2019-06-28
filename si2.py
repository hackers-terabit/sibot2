#!/usr/bin/python
import sys,socket, ssl,requests,json,hashlib
import time,os,getopt,re,feedparser,textwrap
import sqlite3,base64,logging,twitter,SocketServer
import censys.certificates,censys.query
from captcha.image import ImageCaptcha
from threading import Thread,Event,Timer,Lock,RLock
from  Queue import Queue
from unidecode import unidecode
from OTXv2 import OTXv2, IndicatorTypes
from datetime import datetime, timedelta
from telnetsrv.threaded import TelnetHandler, command
import html as htm
from lxml import html
import lxml 


class gv: #global variables
	running=True
	sanity="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@`{}_-=\\/.,[]^:;<>/?=!@#$%^&*()"
	
def n(something):
	if not None is something:
		return something
	else:
		return "Nope"
		
def clean(string,r=""):
	string=n(string)
	string=string.replace(" ","")
	string=string.replace("\r","")
	string=string.replace("\n","")
	string=string.replace("\t","")
	for c in string:
		if None is c:
			c="_"
		elif not c in gv.sanity:
			string=string.replace(c,r)			
	return string		

			
class SimpleClient:
	def __init__(self):
		self.server="chat.freenode.net" #default server
		self.port=6697 #default port
		self.nick="Skuzzy"
		self.nickserv_pass=""
		#the following will be loaded from a config file ideall,actually most of this init section should...
		self.autojoin=[{"Channel":"#skuzzy","Role":["ACTIVE","UNDERAGEQUIET","GREET","AUTOVOICE"],"ADMIN":["funtoo/user/terabit"]},
		{"Channel":"#antispammeta-alerts","Role":["MONITOR"],"ADMIN":["NONE"]},
		{"Channel":"#hackers","Role":["MONITOR"],"ADMIN":["NONE"],"ADMINFOR":"##hackers"},
		{"Channel":"##hackers","Role":["ACTIVE","GREET","AUTOVOICE"],"ADMIN":["taskhive/contributor/terabit","unaffiliated/jabberwock","gateway/web/irccloud.com/x-lvbfkoftjbazzvpx","gateway/web/irccloud.com/x-yhgxokalecruxcja"]},
		{"Channel":"##hackers-threatintel","Role":["ACTIVE","THREATINTEL"],"RSSFILE":"./rsstest"},
		{"Channel":"##malware","Role":["ACTIVE","ADMIN","GREET"],"TAGS":["malware","infection","ransomware","any.run","rat","exploit kit","phish"]}]
		self.captchapath="/usr/share/nginx/www/captcha/"
		self.captchaage=90 #90 second captcha expiration
		self.captchaage=90 #90 second captcha expiration
		self.captchafails=3 #5 tries
		self.uriprefix="https://privateer.one/captcha/"
		self.defaultrole="MONITOR"
		self.threatlog="/usr/share/nginx/www/threatintel/raw.txt"
		self.threatloghtml="/usr/share/nginx/www/threatintel/box"
		self.uriprefix_threatintel="https://privateer.one/threatintel/"
		self.threatpath="/usr/share/nginx/www/threatintel/"
		
	def connect_tls(self):
		try:
			context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	
			context.verify_mode = ssl.CERT_REQUIRED
	
			context.check_hostname = True
			context.load_default_certs()
	
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = context.wrap_socket(s, server_hostname=self.server)
			ssl_sock.connect((self.server, self.port))
			return ssl_sock
		except Exception as e:
			logging.exception("TLS connection error")
			gv.running=False
			
	def usage(self):
		print "Usage: python2 ",os.path.basename(__file__)," [-vh] -s server -p port",('''
		-s	Server name (e.g.: chat.freenode.net)
		-p  Port number (e.g.: 6697)
		-n  Nick name
		-P  Nickserv password
		-captchapath <path> 	specify where to store generated captchas
		-captchaurl  <url> 		specify what url prefix to use (must point to the catchapath location>
		-captchafails <num>		specify the maximum number of failed captcha codes allowed per user
		-captchaage   <num> 	specify how long users have to enter the provided captcha
		-defaultrole <role> 	specify what role the bot plays by default when one isn't specified
		-v  Print this applications current version string
		-h  Display this usage instruction.''')
		sys.exit(1)

	def handle_args(self,args):
		try:
			opts, args = getopt.getopt(sys.argv[1:], "s:p:vh")
		except getopt.GetoptError as err:
			print (str(err))
			self.usage()
		for opt, arg in opts:
			if opt == '-s':
				self.server=arg
			if opt == '-p':
				self.port=int(arg,10)
			if opt == '-n':
				self.nick=arg	
			if opt == '-P':
				self.nickserv_pass=arg
			if opt == '-captchapss':
				self.captchapass=arg
			if opt == '-captchaurl':
				self.uriprefix=arg
			if opt == '-captchafails':
				self.captchafails=int(arg,10)
			if opt == '-captchaage':
				self.captchaage=int(arg,10)
			if opt == '-defaultrole':
				self.defaultrole=arg	
			if opt == '-v':
				print "Version: 0.1a"
				sys.exit(0)
			if opt == '-h':
				self.usage()
		

class IO:
	silence=False
	def __init__(self,ssl_sock):
		self.threads=[]
		self.ssock=ssl_sock
		self.in_queue=Queue()
		self.out_queue=Queue()
		self.out_prio_queue=Queue()
		self.in_event=Event()
		self.out_event=Event()
		self.out_prio_event=Event()

	def start_threads(self):
		in_thread = Thread(target=self.run_input)
		in_thread.daemon=False
		self.threads.append(in_thread)
		in_thread.start()
		
		out_thread = Thread(target=self.run_output)
		out_thread.daemon=False
		self.threads.append(out_thread)
		out_thread.start()
	
	def run_input(self):
		while gv.running:
			try:	
				time.sleep(0.5)
				msg = self.ssock.recv(4096)
				if not None is msg and len(msg) > 0:
					self.in_queue.put(msg)
					self.in_event.set()
			
			except (IOError,ssl.SSLError):
				logging.exception("IO or SSL Error,terminating instance.")
				gv.running=False
				return
			except Exception as e:
				logging.exception("Input exception with message:"+msg)
				continue
		
	def run_output(self):
		while gv.running:
			try:
				self.out_event.wait()  
				if not self.out_prio_queue.empty():
					msg_prio=self.out_prio_queue.get().strip()
					if msg_prio:
						self.ssock.sendall(unidecode(msg_prio)+"\n")
				msg = self.out_queue.get().strip()
				if len(msg) > 0:
					self.ssock.sendall(unidecode(msg)+"\n")
					time.sleep(2) # without this we get k-lined
					
			except (IOError,ssl.SSLError):
				logging.exception("IO or SSL Error,terminating instance.")
				gv.running=False
				return		
			except Exception as e:
				logging.exception( "Output exception with message:"+msg)
				continue
	
	def send(self,msg):
		if self.silence:
			return
		logging.debug("NORMAL->"+msg)
		self.out_event.clear()
		self.out_queue.put(msg)
		self.out_event.set()

	def send_prio(self,msg):
#		if self.silence:
#			return
		logging.debug("PRIO->"+msg)
#		self.out_prio_event.clear()
		self.out_prio_queue.put(msg)
#		self.out_prio_event.set()
		
	def recv(self):
		if not self.in_queue.empty():
			return self.in_queue.get()
		self.in_event.wait()
		msg = self.in_queue.get()
		self.in_event.clear()
		return msg

'''def raw_print(io): #this will ideally be replaced by something that handles server responses
	while True:
		msg=io.recv()
		if not msg is None and len(msg)>0:
			print msg
def input_send(io):
	while True:
		usrmsg=raw_input(">")
		if usrmsg=="/QUIT":
			io.send("QUIT")
			sys.exit(0)
			return
		io.send(usrmsg)
		'''

		
class Registration:
	def __init__(self,name,register_pattern,register_callback,threadme=False,nocase=False):
		self.name=name
		self.pattern=register_pattern
		self.callback=register_callback
		self.threadme=threadme
		self.nocase=nocase
class User:
	def __init__(self,nick,user,host):
		self.nicknames=set()
		self.usernames=set()

		self.nickname=clean(n(nick))
		self.username=clean(n(user))
		self.nicknames.add(clean(n(nick)))

		self.usernames.add(n(clean(user)))
		self.hostname=clean(n(host))
		#print "Adding nick [2] ["+clean(nick)+"] to user with host:"+self.hostname

		self.flags=""
		self.status="UFO"
		self.stats="None"
		self.captcha="None"
		self.captchacode="None"
		self.captchapending=set()
		self.captchafails=0
		self.hostmask=clean(nick+"!"+user+"@"+host)
		self.registered=time.time()
		self.greeted=False
		#print "NEW USER[registered"+str(self.registered)+"]: "+self.hostmask+" KNOWN NICKS:"+'|'.join(self.nicknames)
class Message:
	def __init__(self,user,room,msg):
		self.user=user
		self.room=room.lower()
		self.msg=msg
class Channel:
	def __init__(self,name):
		self.name=clean(name)
		self.users=set()
		self.admins=set()
		self.topic="Not filled"
		self.adminfor=""
		self.role=[]
		self.tags=[]
		self.backlog=[]
		self.pendingvoice=[]
		self.lastmessage=time.time()
		self.regchan=""
		self.rssfeeds=set()			
		self.autovoice=True
		self.jt5s=0
		self.jt1m=0
		self.jt5m=0
		self.jt10m=0
		self.jt30m=0
		
class Eye_Argh_See:
	cblock=RLock()
	def __init__(self,sc,io):
		self.client=sc
		self.io=io
		self.registrar=[]
		self.responder_registrar=[]
		self.channels=set()
		self.users=set() #all users everywhere
		self.identified=False
		self.idbeforejoin=True #nickserv auth
		self.lastnickinfo="" #for when nickserv info is returned,onNICKREGISTERED will use this
		self.lastchannel="" #bleh
		self.agelimit=14 #14 days
		self.callbacksrunning=set()
		self.lastsync=0.0
		self.cbmax=16 #max callbacks
		self.hilitemax=4
		self.cats=0 # boo, 0 cats!! :P
		self.ghosted=False
		self.autovoice=True
		self.realserver=self.client.server
		try:
			self.censys_api_pub=""
			self.censys_api_secret=""
			self.cert=censys.certificates.CensysCertificates(self.censys_api_pub,self.censys_api_secret)
			self.twapi=twitter.Api(consumer_key='',
						consumer_secret='',
						access_token_key='',
						access_token_secret='')
			self.otxapi = OTXv2("")
		except Exception as e:
			logging.exception("API Init exception.")
				
		self.f=open(self.client.threatlog,"rwa+",0)
		self.fh=open(self.client.threatloghtml,"rwa+",0)
		self.ua='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'
			
	def cbcount(self):	
		count=0
		if Eye_Argh_See.cblock.acquire():
			for t in self.callbacksrunning:
				if not t.is_alive():
					self.callbacksrunning.remove(t)
				else:
					count+=1
				Eye_Argh_See.cblock.release()
		return count
		
	def canicall(self):
		return
		if self.cbcount() > self.cbmax:
			logging.debug( "Max callbacks reached,sleeping a for 5secs...")
			time.sleep(5)
			if self.cbcount() > self.cbmax:
				logging.debug( "Still too many callbacks alive,entering a loop state until threads start dying off...")
				while self.cbcount() > self.cbmax:
					time.sleep(1)
	
				logging.debug( "Found a free slot,continuing message processing...")
	#match server messages against regex patterns and dispatch to callbacks
	def server_message_loop(self,msg):
		logging.debug("->"+msg)		
		if not "\n" in msg and not len(msg)<2:
			bullseye=None
			matches=0
		
			#print "+----------------------"
			#print "[D]MSG:"+line
			for r in self.registrar:
				bullseye=r.pattern.match(msg)
				if not  bullseye == None:
						if r.threadme==False:
							r.callback(bullseye,line)
							matches+=1
							logging.debug("Done single-line threadless callback of:"+r.name)
						elif r.threadme==True:	
							#self.canicall()
						
							cb_thread = Thread(target=r.callback,args=(bullseye,msg,))
							cb_thread.daemon = True
							cb_thread.start()
							logging.debug( "Done single-line thread start of:"+r.name)
						'''	if Eye_Argh_See.cblock.acquire():
								self.callbacksrunning.add(cb_thread)
								Eye_Argh_See.cblock.release()'''
			if matches<1:
				logging.debug( "NO MATCHES:"+msg)
#			else:
#				logging.debug("Matched:"+msg)

		else:
			
			lines=msg.split("\n")
			if '\r' in msg:
				lines=msg.split('\r\n')
			bullseye=None
			matches=0
			for line in lines:
				if len(line)<2:
					continue
			#	print "----------------------"
			#	print "[D]MSG:"+line
				for r in self.registrar:
					bullseye=r.pattern.match(line)
					
					
			#		print "[D] Checked against:"+r.name
					if not  None is bullseye:
						if r.threadme==False:
							r.callback(bullseye,line)
							matches+=1
							logging.debug( "Done multi-line threadless callback of:"+r.name)
						elif r.threadme==True:	
							#self.canicall()
							cb_thread = Thread(target=r.callback,args=(bullseye,msg,))
							cb_thread.daemon = True
							cb_thread.start()
							logging.debug( "Done multi-line thread start of:"+r.name)
							'''if Eye_Argh_See.cblock.acquire():
								self.callbacksrunning.add(cb_thread)
								Eye_Argh_See.cblock.release()
							return'''
			if matches<1:
				if msg.startswith("PONG"):
					self.pong(r.pattern.match(msg),msg)

				logging.debug( "No matches:"+str(lines))
				return
#			else:
#				logging.debug("Matches:"+msg)
#				return
	def raw_message_event(self,new_regex,new_callback,name,threadme=False):
		cb=Registration(name,re.compile(new_regex),new_callback,threadme)
		self.registrar.append(cb)
		
	def privmsg_event(self,new_regex,new_callback,name,nocase=False):
		cb=Registration(name,re.compile(new_regex),new_callback,nocase)
		self.responder_registrar.append(cb)

	def autojoin(self):	
		time.sleep(6)
		if self.idbeforejoin and not self.identified:
			logging.info( "Skipping autojoin,I'm not identified with nickserv yet.")
			return

		for chan in self.client.autojoin:
			found=False
			for c in self.channels:
				if c.name.lower() == chan["Channel"].lower():
					c.role=chan["Role"]
					if "TAGS" in chan:
						c.tags = chan["TAGS"]
					if "RegChannel" in chan:
						c.regchan=chan["RegChannel"]
						
					if "ADMIN" in chan:
						for r in chan["ADMIN"]:
							c.admins.add(User("*","*",r))	
					if "ADMINFOR" in chan:
						c.adminfor=chan["ADMINFOR"]
						logging.debug("ADMINFOR added to "+c.name+" for "+c.adminfor)
					if "RSSFILE" in chan:
						with open(chan["RSSFILE"]) as f:
							c.rssfeeds=f.read().split("\n")
								
					found=True
					break
			if not found:
				
				channel=Channel(chan["Channel"])
				if "RegChannel" in chan:
						channel.regchan=chan["RegChannel"]
				if "TAGS" in chan:
						channel.tags = chan["TAGS"]		
				if "ADMIN" in chan:
					for r in chan["ADMIN"]:
						channel.admins.add(User("*","*",r))	
				if "ADMINFOR" in chan:
						channel.adminfor=chan["ADMINFOR"]		
						logging.debug("[2] ADMINFOR added to "+c.name+" for "+c.adminfor)

				if "RSSFILE" in chan:
					with open(chan["RSSFILE"]) as f:
						channel.rssfeeds=f.read().split("\n")
									
				channel.role=chan["Role"]	
				if "ADMIN" in chan:
					for r in chan["ADMIN"]:
							channel.admins.add(User("*","*",r))	
				self.channels.add(channel)
		for c in self.channels:
			self.io.send("JOIN :"+c.name)
					
		logging.info( "***************NICK+USER+AUTOJOIN SENT!***********")
		
		
	def purge(self):
		ublist=[]
		with open("./unban","r") as f:
			data=f.read()
			ublist=data.split("\n")
			for l in ublist:
				print "removing "+l
				if len(l)>3:
					self.io.send("MODE ##hackers -b "+l)
					self.io.send("MODE ##hackers -q "+l)
	def pingloop(self):
		while True:
			time.sleep(30)
			self.io.send("PING :"+self.realserver)
							
	def startme(self):

		#Timer(60.00,self.purge).start()
		#self.db.connectdb()
		#self.channels=self.db.loadchannels()
		#self.users=self.db.loadusers()
		logging.debug( "LOADED USERS+CHANNELS!!")
		self.io.send_prio("CAP REQ :sasl")

#Add raw irc callbacks here
		self.raw_message_event(":\S* NOTICE.*Ident.*",self.ircconnect,"CONNECTION",threadme=False)
		self.raw_message_event(":\S* (.*sasl)",self.saslauth,"SASLAUTH",threadme=False)
		self.raw_message_event(".*(AUTHENTICATE \+)",self.saslauth,"SASLAUTH",threadme=False)
		self.raw_message_event(":\S* (\d{3} .* :SASL.*)",self.saslauth,"SASLAUTH",threadme=False)
		self.raw_message_event("PING :(.*)",self.pong,"PONG",threadme=True)
		self.raw_message_event(":NickServ!NickServ@services\.? NOTICE .* :You are now identified.*",self.onIDENTIFIED,"onIDENTIFIED")
		self.raw_message_event(":.* 353 (.*) =? (.*) .*:(.*)",self.onJOIN,"onJOIN")
		self.raw_message_event(".* 433 .*",self.onBADNICK,"onBADNICK")
		self.raw_message_event(":(.*)!(.*)@(.*) JOIN :?(.*)",self.onUSERJOINED,"onUSERJOINED")

		self.raw_message_event(":(.*)!(.*)@(.*) PART (.*) :(.*)",self.onUSERPART,"onUSERPART")
		self.raw_message_event(":(.*)!(.*)@(.*) QUIT (.*) :(.*)",self.onUSERQUIT,"onUSERQUIT")
		self.raw_message_event(":(.*)!(.*)@(.*) NICK (.*)",self.onNICK,"onNICK")
		self.raw_message_event(":.* 352 .* (.*) (.*) (.*) .* (.*) .* :(.*) .*",self.onNAMES,"onNAMES",threadme=True) 
		self.raw_message_event(":.* 315 .* .* :End of /WHO list.",self.onENDNAMES,"onENDNAMES")
		self.raw_message_event(":.*!~?MetaBot@AntiSpamMeta.+. PRIVMSG #[Aa]ntispammeta :.* risk threat \[(.*)\] - (.*) - .*",self.onASMHIGH,"onASMHIGH",threadme=False)
		#:AntiSpamMeta!~MetaBot@AntiSpamMeta/. PRIVMSG #antispammeta :06Debug risk threat [##hackers] - Captain_Beezay - sending a string designed to trigger a debug test alert, disregard this; ping  !att-##hackers-debug https://antispammeta.net/detectlogs/FD98F034-EF3F-11E6-9F95-0715E25C6CE0.txt

		#self.raw_message_event(":.*!MetaBot@AntiSpamMeta/\. PRIVMSG #[Aa]ntispammeta :.* risk threat \[(.*)\] - (.*) -.*",self.onASMHIGH,threadme=True)
		self.raw_message_event(":NickServ!NickServ@services. NOTICE .* :(.*) is not registered\.",self.onNICKNOTREGISTERED,"onNICKNOTREGISTERED",threadme=False)
		self.raw_message_event(":NickServ!NickServ@services. NOTICE .* :Registered : (.*) \((.*)\)",self.onNICKREGISTERED,"onNICKREGISTERED",threadme=False)
		self.raw_message_event(":NickServ!NickServ@services. NOTICE .* :Information on (.*) \(.*",self.onNICKINFO,"onNICKINFO")
		self.raw_message_event(":(.*)!(.*)@(.*) PRIVMSG "+self.client.nick+" :(.*)",self.onPM,"onPM",threadme=True)
		
		self.raw_message_event(":(.*)!(.*)@(.*) PRIVMSG (.*) :(.*)",self.onPRIVMSG,"onPRIVMSG",threadme=True)
#privmsg callbacks for things like channel commands go below here		
		self.privmsg_event("\.admin (.*)",self.admin,"ADMINISTRATION")
		self.privmsg_event("^[hH][iI][ \.!\?]?$",self.hi,"HI")
		self.privmsg_event("^[hH][eE][lL]+[oO][ \.!\?]?$",self.hi,"HELLO")
		self.privmsg_event(".*",self.highlite,"HILITE")
		self.privmsg_event("^!t (.+)",self.title,"TITLE")
		self.privmsg_event("^!t ?",self.titlebacklog,"TITLE-NOGROUP")
		self.privmsg_event("^[sS]\/(.*)\/(.*)[/ \/]?",self.sed,"SED like substitution")
		self.privmsg_event("^ahoy[\. !,]?.*",self.Ahoy,"AHOY",nocase=True)
		self.privmsg_event("^catpics?",self.catpics,"CATS",nocase=False)
		self.privmsg_event(".*(https*:\/\/.*)[\/\s$]*",self.urlcheck,"URLCHECK")
		self.privmsg_event(" (.*\..*\..*)[\/\s$]*",self.urlcheck2,"URLCHECK2")
		self.privmsg_event(".*",self.lastmessage,"LASTMESSAGE")
		self.privmsg_event(".*[Ii][wW][Aa][Nn][Tt][Cc][aA][Pp][Tt][Cc][Hh][Aa].*",self.theywantcaptcha,"THEYWANTCAPTCHA")
		self.privmsg_event("cert\.(.*) (.*)",self.censys,"CENSYS")
		self.privmsg_event(".*",self.rssbotfeed,"RSSBOT")
		self.privmsg_event("\.last.*",self.backlog,"BACKLOG")
		self.privmsg_event("^\.help.*",self.helpcmd,"HELP")


#main bot loop,just throws everything at server_message_loop		
		while gv.running==True:
			#self.dbsync() #this is the main bot loop,doing the sync here.
			msg=self.io.recv()
			if not msg is None and len(msg)>0:
				#print "[D] "+msg
				self.server_message_loop(msg)
	def ircconnect(self,m,msg):
		self.io.send("PRIVMSG NICKSERV :RELEASE "+self.client.nick+" "+self.client.nickserv_pass)
		time.sleep(3)
		self.io.send("NICK "+self.client.nick)
		self.io.send("USER "+self.client.nick+" "+self.client.nick+" "+self.client.server+" :"+self.client.nick)
		self.io.send("PRIVMSG NICKSERV :IDENTIFY "+self.client.nick+" "+self.client.nickserv_pass)	
		self.autojoin()


	def pong(self,m,msg):
		if not None is m:
			self.io.send("PONG :"+n(m.group(1)))
			self.realserver=n(m.group(1))
			logging.debug("PONG :"+n(m.group(1)))
	def saslauth(self,m,msg):
		if not None is m.group(1):
			msg=m.group(1)
		logging.debug("SASLMSG>"+str(msg))

		if msg.startswith("CAP"):
			self.io.send("AUTHENTICATE PLAIN")
			logging.debug("Sent AUTHENTICATE PLAIN")
		if msg.startswith("AUTHENTICATE +"):
			authstr=('{}\0'
				 '{}\0'
				 '{}'
			).format(self.client.nick,self.client.nick,self.client.nickserv_pass)
			authstr=str(base64.b64encode(authstr))
#			authstr=authstr.decode('utf8').rstrip('\n')
			auth="AUTHENTICATE "+authstr
			logging.debug("Auth string "+auth)
			self.io.send(auth)
#			time.sleep(3)
		if msg.startswith("903"):
			self.io.send("CAP END")
			logging.debug("Sent CAP END")
			self.onIDENTIFIED(None,None)

				
	def onNAMES(self,m,msg):
		usr=User(n(m.group(4)),n(m.group(2)),n(m.group(3)))
		usr.flags=n(m.group(5))
		chan=n(m.group(1)).lower()
		#if "##hackers" == chan.lower():
		#self.io.send("MODE ##hackers +v "+usr.nickname)
			
		#self.db.updateuser(usr)
		for c in self.channels:
			if chan.lower() == c.name.lower() and 'ACTIVE' in c.role:
				self.lastchannel=chan
				c.users.add(usr)
			#	logging.debug( "Adding "+usr.nickname+" ("+usr.hostmask+") to "+chan)
		#		if "##hackers" in  c.name.lower(): #one time thing hopefully :(
		#			self.io.send("MODE ##hackers  +v "+usr.nickname)
		usrfound=False
		for u in self.users:
			if u.hostname.lower() == usr.hostname.lower:
				usrfound=True
				break
		if not usrfound:				
			self.users.add(usr)
				
	def onENDNAMES(self,m,msg):
		pass
	def onNICK(self,m,msg):
		for u in self.users:
			if u.hostname==n(m.group(3)):
				u.nickname=n(m.group(4))
				u.nicknames.add(n(m.group(4)))
				#print "Adding nick [3] ["+n(m.group(4))+"] to user with host:"+u.hostname

	def onNICKINFO(self,m,msg):
		self.lastnickinfo=n(m.group(1))
		
	def onBADNICK(self,m,msg):
		if self.ghosted:
			self.io.send("NICK "+self.client.nick+"_")
			logging.info( "Ghosted,trying:"+self.client.nick+"_")
			self.client.nick=self.client.nick+"_"
		else:
			self.ghosted=True #try to release nick on first ghost
			self.io.send("PRIVMSG NICKSERV :RELEASE "+self.client.nick+" "+self.client.nickserv_pass)
			time.sleep(10)
			self.io.send("NICK "+self.client.nick)
			self.io.send("USER "+self.client.nick+" "+self.client.nick+" "+self.client.server+" :"+self.client.nick)
			self.io.send("PRIVMSG NICKSERV :IDENTIFY "+self.client.nick+" "+self.client.nickserv_pass)	
			
	def onIDENTIFIED(self,m,msg):
		self.identified=True 
		logging.info( "I'm identified now,autojoining...")
		self.io.send("PRIVMSG MEMOSERV :READ NEW")
		self.autojoin()
		self.ghosted=False

	def onJOIN(self,m,msg):
		cname=n(m.group(2)).lower()	

					
		self.io.send("WHO "+cname)
		logging.info( "WHO sent(onJOIN). added channel"+cname)
		chan=Channel(cname)
		
		found=False
		for c in self.channels:
			if c.name.lower() == cname:
				found=True
				#self.db.updatechannel(c)
				break
		if not found:
			chan.role=self.myrole(cname)						
			self.channels.add(chan)
			#self.db.updatechannel(chan)
								
	def onPRIVMSG(self,m,msg):
		logging.debug( "Nick:"+m.group(1)+" User:"+m.group(2)+" Host:"+m.group(3)+" Sender:"+m.group(4)+" Message:"+m.group(5))
		usr=User(n(m.group(1)),n(m.group(2)),n(m.group(3)))
		message=Message(usr,n(m.group(4)).lower(),n(m.group(5)))
		bullseye=None
		
		for r in self.responder_registrar:
			if r.nocase:
				bullseye=r.pattern.match(message.msg,flags=re.IGNORECASE)
				logging.debug("Case insensitive match for:"+r.name)
			else:
				bullseye=r.pattern.match(message.msg)
			if not  bullseye == None:
				r.callback(bullseye,message)
	def onPM(self,m,msg):
		usr=User(n(m.group(1)),n(m.group(2)),n(m.group(3)))
		if self.client.nick.lower() == usr.nickname.lower():
			return
		msg=n(m.group(4))
		for u in self.users:
			if u.hostname.lower() == usr.hostname.lower():
				if "CAPTCHAWAIT" == u.status or "CAPTCHAFAIL" == u.status:
					if self.checkcaptcha(u,msg):
						u.status="CAPTCHAGOOD"
#						for c in u.captchapending:
#							self.io.send("MODE ##hackers +I *!*@"+u.hostname)
#							self.io.send("INVITE "+u.nickname+" ##hackers")
						self.io.send("PRIVMSG "+u.nickname+" :Thank you,please give me a minute to examine your response.")
					#	self.io.send("PRIVMSG "+u.nickname+" :Your humanity is proven.You will be invited and allowed to join within one minute.")
						logging.info( u.nickname+" Is just a normal human being.")
				break
	def onNICKNOTREGISTERED(self,m,msg):
		nick=clean(n(m.group(1))).lower()
		
		for u in self.users:
			if u.nickname.lower() == nick:
				if "BORINGHUMAN" in u.status:
					logging.debug( "Unregistered user <"+u.nickname+"> has already proved his humanity,leaving him alone for now.")
					return
				for c in self.channels:
					if "UNDERAGEQUIET" in c.role:
						self.underagequiet(u,c)
				break
										
	def onNICKREGISTERED(self,m,msg):
		logging.debug( "<NICKINFO>"+msg)
		nick=self.lastnickinfo #shady but w/e
		user=''
		registered=7
		usrfound=False
		if None is nick or len(nick)<1:
			time.sleep(2) #just minor paranoia to avoid a race condition with onUSERJOINED
			nick=self.lastnickinfo
			if None is nick or len(nick)<1:
				return
		nick=nick.replace(" ","")		
		agestr=n(m.group(1))
		if len(agestr)>3:
			logging.debug( "Got agestr: "+agestr)
			registered=time.strptime(agestr,"%b %d %H:%M:%S %Y")
		if not None is registered:
			logging.debug("Nick |"+nick+"| was registered on "+time.strftime("%A %B %d,%Y",registered))
			for u in self.users:
				#logging.debug( "Checking |"+u.nickname+"| vs |"+nick+"|")
				if u.nickname in nick:
					logging.debug( "A match!")
					
					u.registered=time.mktime(registered)
					logging.debug(u.nickname+" Registration time set to: "+str(int(u.registered)))
					user=u
					usrfound=True
					break
		self.lastnickinfo="None"

			
		if usrfound and not "BORINGHUMAN" == user.status and not type(user) is str and not self.client.nick.lower() == user.nickname.lower():
			for c in self.channels:
				if "UNDERAGEQUIET" in c.role:
					self.underagequiet(user,c)
		elif not usrfound:
			logging.debug( "User not found :(")
			
	def underagequiet(self,user,channel):
		return  ##for now
		if not "UNDERAGEQUIET" in channel.role and not "BORINGHUMAN" == user.status:
			logging.debug( "Channel role has no underage quiet enabled:"+channel.name+",Roles:"+''.join(channel.role))
			return 
		logging.debug( "Underage user bouncer checking things out...")
		if not user.nickname.lower() == self.client.nick.lower() and not None is user:
			under,age=self.underagecheck(user)
			if under:
				logging.info( "User "+user.nickname+" is underage!! quieting as role permits.")
				
				logging.debug( channel.name+" Has underagequiet enabled.")
				for u in self.users:
					if user.hostname.lower() == u.hostname.lower() and not u.status == "CAPTCHAWAIT":	
						self.quiet(u,channel)
						u.status="CAPTCHAWAIT"
						url,code=self.makecaptcha(u,channel)
						u.captchacode=code
						self.io.send("PRIVMSG "+u.nickname+" :I am a channel bot for "+channel.name+" Your nickname or account age is too low or your account is not registered at all.")
						self.io.send("PRIVMSG "+u.nickname+" :Apologies for the inconvenience but can you help us keep automated spam bots out of "+channel.name+" By opening the following link in your browser and typing the text you see on there in this window?")
						self.io.send("PRIVMSG "+u.nickname+" :Link: "+url)
						self.io.send("PRIVMSG "+u.nickname+" :This code will expire after one minute. You will never have to do this again so long as you are using this nickname and host.")
						logging.info( "Captcha message sent to user:"+u.nickname)
						return
				logging.info( "User not in our user list.")
						
	def underagecheck(self,usr):
		for u in self.users:
			if usr.nickname == u.nickname:
				
				now=time.time()
				age=(int(now-u.registered))/86400
				logging.debug( "User "+u.nickname+" has been registered for "+str(age)+" days.Limit is:"+str(self.agelimit))
				underage=False
				if age < self.agelimit:
					underage=True
				else:
					underage=False
				return underage,age
		return True,0
		
		
	def onUSERJOINED(self,m,msg):
		usr=User(n(m.group(1)),n(m.group(2)),n(m.group(3)))
		#self.io.send("MODE ##hackers +v "+usr.nickname)
		if usr.nickname.lower() == self.client.nick.lower():
			return
		usrfound=False
		for u in self.users:
			if usr.hostname.lower() == u.hostname.lower():
				if "BORINGHUMAN" == u.status:
					usrfound=True
					usr=u
					break
		
		if not usrfound:
			self.users.add(usr)
		
		chan=clean(n(m.group(4)).lower())
		channel=''
		chanfound=False
		for c in self.channels:
			if chan == c.name:
				c.users.add(usr)
				channel=c
				chanfound=True
				break
		if not chanfound:
			logging.debug( "No channel found on join,adding a new one")
			channel=Channel(chan.lower())
			channel.role=self.client.defaultrole
			for c in self.client.autojoin:
				if c["Channel"].lower() == chan:
					channel.role=c["Role"]
					if "RegChannel" in c:
						channel.regchan=c["RegChannel"]
						
					if "ADMIN" in chan:
						for r in c["ADMIN"]:
							channel.admins.add(User("*","*",r))
			self.channels.add(channel)
			
		for c in self.channels:	
			if c.name.lower() == channel.name.lower():
				c.jt5s+=1
				c.jt1m+=1
				c.jt5m+=1
				c.jt10m+=1
				c.jt30m+=1
				channel=c
				break
			
		#self.db.updateuser(usr)
		
		logging.info( "User "+usr.hostmask+" has joined "+chan+",db updated.")
		nick=usr.nickname.replace(" ","")
		logging.debug( "Query registration on |"+nick+"|")
		if "UNDERAGEQUIET" in channel.role:
			self.io.send("PRIVMSG NICKSERV :INFO "+nick)
		if "ACTIVE" in channel.role:
			if "root" == usr.username.lower():
				self.io.send("PRIVMSG "+usr.nickname+" :Hi, I'm a channel bot for "+channel.name+", I noticed that you are logged in as root. It is generally considered to be a bad security practice to use IRC or any other client software as root. running as root unnecessarily increases the impact potential vulnerabilities in your client can have. Please ask in "+channel.name+" If you have any questions.") 
		if "REGOVERFLOW" in channel.role:
			for u in self.users:
				if u.hostname.lower() == usr.hostname.lower() and not u.status == "CAPTCHAWAIT":
					
					if channel.jt5s < 3 and channel.jt1m < 10 and channel.jt5m < 15 and channel.jt10m < 20 and channel.jt30m<30:
						self.io.send("MODE "+channel.regchan+" +I *!*@"+u.hostname)
						self.io.send("INVITE "+u.nickname+" "+channel.regchan)
						self.io.send("PRIVMSG "+channel.name+" :"+u.nickname+":You are now allowed to join "+channel.regchan+" ,If you are still unable to do so please follow the instruction in the topic")
					u.status="CAPTCHACHOICE"
					#self.io.send("PRIVMSG "+channel.name+" :Welcome "+u.nickname+", Please register your nickname to join "+channel.regchan+" (See https://freenode.net/kb/answer/registration) . Alternatively type 'iwantcaptcha' to prove that you're a human.")
					break
		if "AUTOVOICE" in channel.role or channel.name.lower() == "##hackers":
			for c in self.channels:
				if c.name.lower() == channel.name.lower():
					voicethem=False
					p23=p22=p1080=p7547=pbl=wl=None
					if  c.autovoice==True and c.jt5s < 3 and c.jt1m < 10 and c.jt5m < 15 and c.jt10m < 20 and c.jt30m<30:
						try:
							p23=self.portcheck(usr.hostname,23)
							p22=self.portcheck(usr.hostname,22)
							p1080=self.portcheck(usr.hostname,1080)
							p7547=self.portcheck(usr.hostname,7547)
							pbl=self.blacklisted(usr.hostname)
							wl=self.whitelisted(usr.hostname)
							
							if wl: 
								voicethem=True
							elif not wl==True and pbl==True:
								voicethem=False	
								logging.debug("Blacklist found for "+usr.hostmask)
						#	elif not pbl==True and ( "gateway/shell/" in usr.hostname[0:len("gateway/shell/")] or "gateway/web/" in usr.hostname[0:len("gateway/web/")]):	
								#voicethem=True
								#logging.debug("Voicing "+usr.nickname+" due to a web/shell gateway hostmask.")
							elif  not wl==True and p7547==False and p1080==False  and p23==False:
								voicethem=True	
							elif p22==True:
								p80=self.portcheck(usr.hostname,80)
								p8080=self.portcheck(usr.hostname,8080)
								if p80==False and p8080==False:
									voicethem=True
									p22=False
									logging.debug("Overlooking an open port 22 due to a closed 80 and 8080")
								else:
									voicethem=False
									logging.debug("No voice for "+usr.nickname+" Due to an open http port and ssh port")
							else:
								voicethem=False
								logging.debug("Electing no voice for "+usr.nickname+" due to lack of matches,something went wrong!")		
						except Exception as e:
							logging.exception("Error looking up blacklist and portcheck")
							
						if voicethem==True:
							self.io.send("MODE "+c.name+" +v "+usr.nickname)		
							logging.debug("AUTOVOICED:"+usr.nickname+" In:"+c.name)
						else:
							logging.debug("NO AUTOVOICE for:"+usr.nickname)	
							opened=""
							if p23:
								opened+="Port Open 23,"
							if p22:
								opened+="Port Open 22 (and http[80,8080]),"
							if p1080:
								opened+="Port Open 1080,"
							if p7547:
								opened+="Port Open 7547,"
							if pbl:
								opened+="Blacklisted"				
							else:
								c.pendingvoice.append(usr.nickname)
								
							self.io.send("PRIVMSG #hackers :Possible spambot for "+usr.hostmask+" Not autovoicing them. Reason ["+opened+"]" )
							#if user.nickname p22:
								#for u in self.users:
									#if usr.hostname.lower() == u.hostname.lower() and not u.status == "CAPTCHAWAIT":	
										#u.status="CAPTCHAWAIT"
										#url,code=self.makecaptcha(u,channel)
										#u.captchacode=code
										#self.io.send("PRIVMSG "+u.nickname+" :Hi, I am the channel bot for "+channel.name+" , My spam bot detection system flagged your IP as a potential risk. Please consider registering your nickname and getting a cloak from freenode staff in #freenode to avoid this in the future")
										#self.io.send("PRIVMSG "+u.nickname+" :In the mean time, please wait for an admin to allow you to speak or open this link in your browser and type in the value of the code in this window so that I can check whether you are a human or not:")
										#self.io.send("PRIVMSG "+u.nickname+" :"+url)
					else:
						logging.info("AUTOVOICE OFF OR JOIN RATE IS TOO HIGH FOR "+channel.name)	
						self.io.send("PRIVMSG #hackers :AUTOVOICE OFF OR JOIN RATE IS TOO HIGH FOR "+usr.hostmask+" in "+channel.name)

		#if not type(channel) is str:
			#self.db.updatechannel(channel)
					
	def onUSERPART(self,m,msg):
		usr=User(n(m.group(1)),n(m.group(2)),n(m.group(3)))
		chan=n(m.group(4)).lower()
		channel=''
		for c in self.channels:
			if chan == c.name:
				for u in c.users:
					if usr.hostmask.lower() == u.hostmask.lower():
						c.users.remove(u)
						channel=c
						break
				break
		#if not type(channel) is str:
			#self.db.updatechannel(channel)					
		logging.info( "User "+usr.hostmask+" has left "+chan)
		
	def onUSERQUIT(self,m,msg):
		self.onUSERPART(m,msg) #for right now treat PART and QUIT the same.
	
	def onASMHIGH(self,m,msg):
		logging.info( "ANTISPAMMETA HIGH DETECTION")
		chan=clean(n(m.group(1)))
		spammer=clean(n(m.group(2)))
		spammeruser=''
		channel=''
		usrfound=False
		for u in self.users:
			for nick in u.nicknames:
				if  spammer.lower() == nick.lower:
					spammeruser=u
					usrfound=True
					break
			if u.nickname.lower() == spammer.lower():
				spammeruser=u
				usrfound=True
				break
			if usrfound:
				break
						
		if not usrfound:
			for c in self.channels:
				if "ACTIVE" in c.role and c.name.lower() == chan.lower():
					self.io.send("MODE "+c.name+" -v "+spammer)
					self.io.send("MODE "+c.name+" +q "+spammer)
					
					logging.info("An unknown spammer "+spammer+" has been devoiced")
		else:				
			logging.info( "A known user"+spammer+" is reported as a spammer by Antispammeta")
			self.blacklist(spammeruser.hostname,why="Antispammeta alert")
			for c in self.channels:
				if not type(spammeruser) is str and "ACTIVE" in c.role and c.name.lower() in chan.lower():
					logging.info( "Quieting ["+c.name+"]: "+spammeruser.nickname)
					self.quiet(spammeruser,c,notify=False) #quiet the user wherever possible
					self.io.send("MODE "+c.name+" -v "+spammeruser.nickname)
					self.io.send("MODE "+c.name+" +q "+"*!*@"+spammeruser.hostname)
			
	def myrole(self,cname):
		role=[self.client.defaultrole]
		for c in self.channels:
			if c.name.lower() == cname.lower():
				role=c.role
		return role
		
	def backlog(self,m,message):
		for c in self.channels:
			if c.name.lower() == message.room.lower():
				for msg in c.backlog:
					rmsg="PRIVMSG "+message.user.nickname+" :<"+msg.user.nickname+"> "+msg.msg
					self.io.send(rmsg.replace("\n",""))	
	def admin(self,m,message):
		cmd=n(m.group(1))
		logging.debug("Admin command check...")
		for c in self.channels:
			if c.adminfor=="" and c.name.lower() == message.room.lower():
				logging.debug(c.name+" found!")
				for a in c.admins:
					logging.debug("Checking if "+a.hostname+" is "+message.user.hostname)
					if message.user.hostname.lower() == a.hostname.lower():
						logging.debug("Found an admin,processing commands...")
						self.admincmd(cmd,message.room)
						return
			elif len(c.adminfor)>1 and  c.name.lower() == message.room.lower():
				logging.debug("Checking adminfor - "+c.adminfor)
				for cc in self.channels:
					if cc.name.lower() == c.adminfor:
						logging.debug(cc.name+" found - adminfor!")
						for a in cc.admins:
							logging.debug("Checking x2 if "+a.hostname+" is "+message.user.hostname)
							if message.user.hostname.lower() == a.hostname.lower():
								logging.debug("Found an admin,processing commands...")
								self.admincmd(cmd,cc.name,realroom=c.name)
								return
			
			
	def admincmd(self,cmd,cname,realroom=""):
		logging.debug("Admin cmd:|"+cmd+"| admin channel:"+cname)
		if len(realroom) < 2:
			realroom=cname
			
		if len(cmd)>=len("QUIT") and cmd=="QUIT":
			self.io.send("QUIT")
			gv.running=False
			return
		elif len(cmd)>=len("PART") and  cmd.lower() == "part":
			self.io.send("PART "+cname)
			return
		elif len(cmd)>=len("SILENCE") and cmd.lower() == "silence":
			self.io.silence=True
			return
		elif len(cmd)>=len("quiet") and "QUIET" == cmd[:len("quiet")].lower():
			p=re.compile("[Qq][uU][iI][eE][tT] +(.*) ?")
			m=p.match(cmd)
			if not None is m:
				self.io.send("MODE "+cname+" +q "+clean(n(m.group(1))))
			else:
				logging.info("Admin command to quiet was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)
			return
		elif len(cmd)>=len("unquiet") and "UNQUIET" == cmd[:len("unquiet")].lower():
			p=re.compile("[uU][nN][Qq][uU][iI][eE][tT] +(.*) ?")
			m=p.match(cmd)
			if not None is m:
				self.io.send("MODE "+cname+" -q "+clean(n(m.group(1))))
			else:
				logging.info("Admin command to unquiet was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)	
			return
		elif len(cmd)>=len("voice") and  "voice" == cmd[:len("voice")].lower():
			p=re.compile("[vV][oO][iI][cC][eE] +(.*)")
			m=p.match(cmd)
			if not None is m:
				nicks=m.group(1).split(" ")
				if len(nicks)>0:
					for nick in nicks:
						self.io.send("MODE "+cname+" +v "+clean(n(nick)))
				elif len(m.group(1))>0:
					self.io.send("MODE "+cname+" +v "+clean(n(m.group(1))))		
				
			else:
				logging.info("Admin command to voice was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)
			return
		elif len(cmd)>=len("devoice") and "devoice" == cmd[:len("devoice")].lower():
			p=re.compile("[dD][eE][vV][oO][iI][cC][eE] +(.*) ?")
			m=p.match(cmd)
			if not None is m:
				self.io.send("MODE "+cname+" -v "+clean(n(m.group(1))))
			else:
				logging.info("Admin command to unquiet was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)	
			return	
		elif len(cmd)>=len("ban") and "ban" == cmd[:len("ban")].lower():
			p=re.compile("[bB][aA][nN] +(.*) ?")
			m=p.match(cmd)
			if not None is m:
				self.io.send("MODE "+cname+" +b "+clean(n(m.group(1))))
			else:
				logging.info("Admin command to voice was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)
			return
		elif len(cmd)>=len("unban") and "unban" == cmd[:len("unban")].lower():
			p=re.compile("[uU][nN][bB][aA][nN] +(.*) ?")
			m=p.match(cmd)
			if not None is m:
				self.io.send("MODE "+cname+" -b "+clean(n(m.group(1))))
			else:
				logging.info("Admin command to devoice was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)	
			return
		elif len(cmd)>=len("kick") and "kick" == cmd[:len("kick")].lower():
			p=re.compile("[kK][iI][cC][kK] +(.*) ?")
			m=p.match(cmd)
			if not None is m:
				self.io.send("KICK "+cname+" "+clean(n(m.group(1))))
			else:
				logging.info("Admin command to kick was dropped due to regex match failure,channel:"+cname+",message:"+cmd	)
			return
		elif len(cmd)>=len("tooloud") and"tooloud" == cmd[:len("tooloud")].lower():
			self.autovoice=False
			for c in self.channels:
				logging.debug("Processing too loud against channel:"+c.name)
				if c.name.lower() == cname.lower().replace(" ",""):
					c.autovoice=False
					self.io.send("PRIVMSG "+realroom+" :Yikes,oook :(")
					logging.debug("DISABLED AUTOVOICE IN:"+c.name)
					
			return			
		elif len(cmd)>=len("tooquiet") and"tooquiet" == cmd[:len("tooquiet")].lower():
			self.io.send("PRIVMSG "+realroom+" :\o/")
			self.autovoice=True
			for c in self.channels:
				if c.name.lower == cname.lower():
					c.autovoice=True
				
			return		
		
		elif len(cmd)>=len("blacklist") and "blacklist" == cmd[:len("blacklist")].lower():
			self.io.send("PRIVMSG "+realroom+" :10-4")
			p=re.compile("blacklist +(.*)")
			m=p.match(cmd)
			c=n(m.group(1)).split(" ")
			if len(c)<2:
				self.blacklist(n(m.group(1)))
				
			else:
				self.blacklist(c[0],why=' '.join(c[1:]))
			logging.info(n(m.group(1))+"Has been blacklisted")
			return
		elif len(cmd)>=len("whitelist") and "whitelist" == cmd[:len("whitelist")].lower():
			self.io.send("PRIVMSG "+realroom+" :10-4")
			p=re.compile("whitelist +(.*)")
			m=p.match(cmd)
			self.whitelist(n(m.group(1)))
			logging.info(n(m.group(1))+"Has been blacklisted")
			return
		elif len(cmd)>=len("pendingvoice") and "pendingvoice" == cmd[:len("pendingvoice")].lower():
			self.io.send("PRIVMSG "+realroom+" :10-4")
			for c in self.channels:
				if c.name.lower() == cname.lower():	
					logging.debug("PENDING VOICE: found channel - "+c.name+" list:"+' '.join(c.pendingvoice))
					for nickname in c.pendingvoice:
						self.io.send("MODE "+c.name+" +v "+nickname)
					c.pendingvoice=[]	
				return
			logging.debug("PENDING VOICE:channel "+cname+" Not found.")
		elif len(cmd)>=len("say") and "say" == cmd[0:len("say")].lower():
			p=re.compile("say (.*)")
			m=p.match(cmd)
			self.io.send("PRIVMSG "+cname+" :"+n(m.group(1)).rstrip())
				
	def helpcmd(self,m,message):
		self.io.send("PRIVMSG "+message.user.nickname+" :!t <url> #Website Title lookup")
		self.io.send("PRIVMSG "+message.user.nickname+" :!t 		 #Website Title lookup - most recent URL posted in the channel.")
		self.io.send("PRIVMSG "+message.user.nickname+" :s/oldtext/newtext/  #Replace the most recent oldtext posted with newtext")
		self.io.send("PRIVMSG "+message.user.nickname+" :ahoy #Ahoy sailor!")
		self.io.send("PRIVMSG "+message.user.nickname+" :catpics  #I haz catz")
		self.io.send("PRIVMSG "+message.user.nickname+" :cert 	# Censys.io certificate information lookup ")
		self.io.send("PRIVMSG "+message.user.nickname+" :.admin # Administrator commands")
		self.io.send("PRIVMSG "+message.user.nickname+" :	.admin <ban|unban|voice|devoice|quiet|unquiet|kick> <nickname> # self explanatory")
		self.io.send("PRIVMSG "+message.user.nickname+" :	.admin tooloud  #stop autovoicing users")
		self.io.send("PRIVMSG "+message.user.nickname+" :	.admin tooquiet #start autovoicing users")
		self.io.send("PRIVMSG "+message.user.nickname+" :	.admin blacklist <hostname> [Reason] #blacklist a hostname,hostnames blacklisted won't be autovoiced")
		self.io.send("PRIVMSG "+message.user.nickname+" :	.admin whitelist <hostname> #add a hostname to a whitelist, this has precedence over blacklist")
		self.io.send("PRIVMSG "+message.user.nickname+" :	.admin voiceall #voice all nicks currently not auto-voiced due to blacklist or anti-spam detection.")
					
	def greet(self,m,message,stamp):
		role=self.myrole(message.room)
		logging.debug( "Got greet,role:"+''.join(role))
		if time.time() - stamp <= 30: #if there was a message since the timer was set,exit!
			logging.debug("Someone spoke in "+message.room+" Since greeting timer started,skipping greeting user:"+message.user.nickname)
			for u in self.users:
				if u.hostname.lower() == message.user.hostname.lower():
					u.greeted=True
					break
			return
		if "GREET" in role:
			for u in self.users:
				if not u.greeted and u.hostname.lower() == message.user.hostname.lower():
					self.io.send("PRIVMSG "+message.room+" :Hi there "+message.user.nickname+". Welcome to "+message.room+". If you don't get a response soon,be patient and wait a bit. Someone who can help you might be away or busy.")
					u.greeted=True
					break
		if "GREETOVERFLOW" in role:
			for u in self.users:
				if not u.greeted and u.hostname.lower() == message.user.hostname.lower():
					self.io.send("PRIVMSG "+message.room+" :Welcome "+u.nickname+", Please register your nickname to join "+channel.regchan+" (See https://freenode.net/kb/answer/registration) . Alternatively type 'iwantcaptcha' to prove that you're a human.")
					u.greeted=True
					break
	def portcheck(self,ip,port):
		if not type(ip) is str:
			return False
		try:	
			sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sk.settimeout(3.0)
			logging.debug("Checking port: "+ip+":"+str(port))
			res = sk.connect_ex((ip,port))
			if res==0:
				logging.debug("Open port for:"+ip+":"+str(port))
				return True
			else:
				logging.debug("Closed port for:"+ip+":"+str(port))
				return False 
		except Exception as e:
			return False
	def whitelist(self,host):
		if "~" in host or "*" in host:
			return
		with open("/home/skuzzy/whitelist","a+") as f:
			f.write(host+"\n")
	def whitelisted(self,host):
		with open("/home/skuzzy/whitelist","r+") as f:
			for line in f.read().split("\r\n"):
				if not None is line and line.lower().rstrip() == host.lower().rstrip():
					return True
		return False 
						
	def blacklist(self,host,why=""):
		if "~" in host or "*" in host:
			return
			
		with open("/home/skuzzy/scraped/blacklist","a+") as f:
			f.write(n(host)+" #"+why+"\n")
			
	def blacklisted(self,host):
		with open("/home/skuzzy/scraped/IPv4","r+") as f:
			for line in f.read().split("\n"):
				
				if line.split(" ")[0].lower()==host.lower():
					logging.info("Blacklisted host "+host+" Found")
					return True
		with open("/home/skuzzy/scraped/blacklist","r+") as f:
			for line in f.read().split("\n"):
				if line.split(" ")[0].lower().rstrip()==host.lower().rstrip():
					logging.info("Blacklisted host "+host+" Found")
					return True			
		with open("/home/skuzzy/scraped/hostname","r+") as f:
			for line in f.read().split("\n"):
				if line.split(" ")[0].lower()==host.lower():
					logging.info("Blacklisted host "+host+" Found")
					return True
		with open("/home/skuzzy/scraped/domain","r+") as f:
			for line in f.read().split("\n"):
				if line.split(" ")[0].lower()==host.lower():
					logging.info("Blacklisted host "+host+" Found")
					return True
		with open("/home/skuzzy/regexblacklist","a+") as f:
			for line in f.read().split("\n"):
				if len(line)>0:
					try:
						if not None is re.compile(line).match(host.lower()):
							logging.info("Regex blacklist match")
							return True
					except Exception as e:
						logging.exception("regexblacklist error")
		return False 
													
	def hi(self,m,message):
		for c in self.channels:
			if c.name.lower() == message.room.lower():
				stamp=time.time()
				Timer(30.00,self.greet,args=[m,message,stamp]).start()
				return
	def urlcheck2(self,m,message):
		url=n(m.group(1))
		if not "NONE"==url:
			logging.debug("URLCHECK2 on "+url)
			self.urllookup("http://"+url,url,message.room)
	def urlcheck(self,m,message):
		url=n(m.group(1))		
		if not "NONE"==url:
			p=re.compile(".*/(.*\..*\..*)[/\s].*")
			m=p.match(url)
			if not None is m:
				domain=n(m.group(1))
				logging.debug("URLCHECK on "+url+" found domain:"+domain)
				self.urllookup(url,domain,message.room)
			else:
				logging.debug("URLCHECK on "+url+" found no doamin")
				self.urllookup(url,"",message.room)
	def urllookup(self,url,domain,room):
		urlines=[]
		with open("/home/skuzzy/scraped/URL","r+") as f:
			urlines=f.read().split("\n")
		for l in urlines:
			if url.lower().strip()==l.lower().strip():
				for c in self.channels:
					if c.name.lower() == room.lower():
						if not "MONITOR" in c.role:
							warning="PRIVMSG "+room+" :^^^^^^^ WARNING,THE RECENTLY POSTED URL "+url.rstrip()+" IS LIKELY A DANGEROUS SITE,OPEN AT YOUR OWN PERIL ^^^^^"
							warning=warning.replace("\r\n","")
							warning=warning.replace("\n","")
							
							self.io.send(warning)
						return
		if len(domain)>2 and self.blacklisted(domain):
			for c in self.channels:
				if c.name.lower() == room.lower():				
					if not "MONITOR" in c.role:
						warning="PRIVMSG "+room+" :^^^^^^^ WARNING,THE RECENTLY POSTED URL "+url.rstrip()+" IS LIKELY A DANGEROUS SITE,OPEN AT YOUR OWN PERIL ^^^^^"
						warning=warning.replace("\r\n","")
						warning=warning.replace("\n","")
						warning=warning.replace(u"\n","")
						self.io.send(warning)
						return
						
	def titlebacklog(self,m,message):
		if len(message.msg) > 4:
			return
		try:
			for c in self.channels:
				if c.name.lower() == message.room.lower():
					if not "MONITOR" in c.role:	
						count=len(c.backlog)
						if count >0:
							p=re.compile(".*(https?://.*) ?$")
							p2=re.compile(" ?(\w\.\w.\w) ?")
							for i in range(count-1,0,-1):
								linkm=p.match(c.backlog[i].msg)
								if None is linkm:
									linkm=p2.match(c.backlog[i].msg)
									
								if not None is linkm:
									link=linkm.group(1)
									if not "http://" in link.lower() and not "https://" in link.lower():
										link="http://"+link
									title_thread = Thread(target=self.titlegrabber,args=[link.replace(" ","").replace("\n","").replace("\r",""),c.name])
									title_thread.daemon=False
									title_thread.start()
									return
					break						
		except Exception as e:
			logging.exception("Titlebacklog command  exception!")	
							
	def title(self,m,message):
		try:
			for c in self.channels:
				if c.name.lower() == message.room.lower():
					if not "MONITOR" in c.role:
						if not None is m:
							p=re.compile(".*(https?://.*) ?$")
							linkm=p.match(message.msg)
							if None is linkm:
								p=re.compile(" ?(\w\.\w.\w) ?")
								linkm=p.match(message.msg)
								
									
							if not None is linkm:
								link=linkm.group(1)
								if not "http://" in link.lower() and not "https://" in link.lower():
									link="http://"+link
								title_thread = Thread(target=self.titlegrabber,args=[link.replace(" ","").replace("\n","").replace("\r",""),message.room])
								title_thread.daemon=False
								title_thread.start()
								return											
					break			
		except Exception as e:
			logging.exception("Title command  exception!")						
			
	def titlegrabber(self,link,to):	
		try:					
			if not None is link and len(link)>0 and not None is to and len(to)>0:
				headers = {'User-Agent':self.ua}
				page=requests.get(link,timeout=4,headers=headers)
				if not None is page:
					p=html.fromstring(page.content)
					
					title=p.findtext(".//title")
					#title=str(chr(3)+"9").encode('ascii')+n(title)
					if not None is title and len(title)>0:
						self.io.send("PRIVMSG "+clean(to)+" :"+title.replace("\n","").replace("\r",""))
						return
		except Exception as e:
			logging.exception("Title grab exception!")		
			
	def sed(self,m,message):
		old=n(m.group(1))
		new=n(m.group(2))
		for c in self.channels:
			if c.name.lower() == message.room.lower():
				count=len(c.backlog)
				if count > 0:
					for i in range(count-2,0,-1):
						if not message.msg==c.backlog[i].msg and not "s/" in c.backlog[i].msg.lower() and old in c.backlog[i].msg and c.backlog[i].user.hostname.lower() == message.user.hostname:
							replaced=c.backlog[i].msg.replace(old,new)
							self.io.send("PRIVMSG "+message.room+" :"+message.user.nickname+" meant to say: "+replaced.replace("\n","").replace("\r",""))
							return
				break
				
	def Ahoy(self,m,message):
		role=self.myrole(message.room)
		if "ACTIVE" in role:
			self.io.send("PRIVMSG "+message.room+" :"+message.user.nickname+":Ahoy sailor!!")

	def wherehaveibeen(self,m,message):
		if message.msg.lower() == "skuzzy: where have you been?":
			self.io.send("PRIVMSG "+message.room+" :A Firewall :(")
					
	def rssbotfeed(self,m,message):
		if message.room.lower() == "##hackers-threatintel" and message.user.nickname.lower() == 'rssbot' and message.user.hostname.lower() == 'ill.blast.your.azz.if.uwantmy.info':
			with open("/usr/share/nginx/www/threatintel/raw.txt","a+",0) as lf:
				lf.write("[RSS] "+message.msg+"\n")
			
			
	def catpics(self,m,message):
		if self.cats <5:
			cat_thread = Thread(target=self.elgato,args=(message.user.nickname,message.room,))
			cat_thread.daemon = True
			cat_thread.start()
			self.cats+=1
		
	def elgato(self,nick,channel):
		response=requests.get("https://api.thecatapi.com/api/images/get?MTU3NDAz",allow_redirects=False)
		if response.status_code==302 and 'Location' in response.headers:
			location=response.headers["Location"]
			if not None is location and len(location)>10 and "https://" in location[:10]:
				 self.io.send("PRIVMSG "+channel+" :"+nick+" Meooow "+location)
		self.cats-=1
	def censys(self,m,message):
		if None is m:
			return
		cmd=n(m.group(1))
		query=n(m.group(2))
		if len(cmd)<3 or len(query)<3:
			return
		if cmd.lower()[:4] =="sha2":
			censys_thread = Thread(target=self.censys_sha2,args=[query,message.room,message.user])
			censys_thread.daemon = False
			censys_thread.start()
		elif cmd.lower()[:6] =="search":
			censys_thread = Thread(target=self.censys_search,args=[query,message.room,message.user])
			censys_thread.daemon = False
			censys_thread.start()	
	def censys_sha2(self,query,cname,user):
		result=self.cert.view(query)
		if not "parsed" in result or len(result["parsed"])<1:
			self.io.send("PRIVMSG "+cname+" :"+user.nickname+":Error with the query,be sure to specify a properly formatted sha256 fingerprint of the certificate you're looking up.")
			return
		else:
			valid_start=result["parsed"]["validity"]["start"]
			valid_end=result["parsed"]["validity"]["end"]
			subjectdn=result["parsed"]["subject_dn"]
			issuer_cn=result["parsed"]["issuer"]["common_name"][0]
			issuer_org=result["parsed"]["issuer"]["organization"][0]
			self.io.send("PRIVMSG "+cname+":"+user.nickname+":Subject domain:'"+subjectdn+"' Issuer Common Name:'"+issuer_cn+
			"' Issuer Organization:'"+issuer_org+"' Valid From:'"+valid_start+"' To:'"+valid_end+"'")
			return
			
	def censys_search(self,query,cname,user):
		search_fields=["parsed.subject_dn","parsed.validity.start","parsed.validity.end","parsed.fingerprint_sha256","parsed.issuer.common_name","parsed.issuer.organization"]
		result=self.cert.search(query,max_records=2,fields=search_fields)
		if None is result :
			self.io.send("PRIVMSG "+cname+":"+user.nickname+":Error with the query")
			logging.info("Bad censys_search query:"+query+"res:"+result)
			return
		else:
			for c in result:
				valid_start=c["parsed.validity.start"][0]
				valid_end=c["parsed.validity.end"][0]
				subjectdn=c["parsed.subject_dn"][0]
				issuer_cn=c["parsed.issuer.common_name"][0]
				issuer_org=c["parsed.issuer.organization"][0]
				sha256=c["parsed.fingerprint_sha256"][0]			
				self.io.send("PRIVMSG "+cname+" :"+user.nickname+":Subject domain:'"+subjectdn+"' Issuer Common Name:'"+issuer_cn+
				"' Issuer Organization:'"+issuer_org+"' Valid From:'"+valid_start+"' To:'"+valid_end+"' SHA256 Fingerprint:"+sha256)
			return
	def lastmessage(self,m,message):
		room=clean(n(message.room))
		for c in self.channels:
			if c.name.lower() == room.lower():
				c.lastmessage=time.time()
				c.backlog.append(message)
				if len(c.backlog)>100:
					c.backlog.remove(c.backlog[0])
				return
				
	def highlite(self,m,message):
		highlites=set()
		channel=''
		for c in self.channels:
			#logging.debug( "HL works")
			
			if message.room == c.name:
				if "REGOVERFLOW" in c.role:
					return
				channel=c
				logging.debug( "["+message.room+"]hilite check: "+c.name)
				for u in self.users:
					#logging.debug( "checking "+u.nickname+" in "+message.room)
					if len(u.nickname)>2 and clean(u.nickname.lower()) in clean(message.msg.lower()):
						highlites.add(u.nickname)
		response=""				
		for nick in highlites:
			response+=nick+" "
		if len(highlites)>0:
			#self.io.send("PRIVMSG "+message.room+" :[HL] "+response)
			logging.debug( "[HL]["+str(len(highlites))+": "+message.room+"> "+response)
		if len(highlites)>=self.hilitemax and not type(channel) is str:
			hostmask="*!*@"+message.user.hostname
			self.quiet(message.user,channel,notify=True)	
			logging.info( "quieted "+hostmask)
			
	def theywantcaptcha(self,m,message):
		for c in self.channels:
			if c.name.lower() == message.room.lower():
				if "REGOVERFLOW" in c.role:
					url,code=self.makecaptcha(message.user,c)
					self.io.send("PRIVMSG "+c.name+" :You got it "+message.user.nickname+"! Please check PM(Private Message) from me.")		
					self.io.send("PRIVMSG "+message.user.nickname+
					" :Please open the following link in youur web browser and type the code you see there in this window/PM: "+url)
					for u in self.users:
						if u.hostname.lower() == message.user.hostname.lower():
							u.status="CAPTCHAWAIT"
							u.captchacode=code
							break
							
					break
	def readable(self,s):
		allowed="ABCDEFGHJKLMNPRSTUVWXYZ2345689"
		for c in s:
			if not c in allowed:
				s=s.replace(c,"")
		return s
				
	def makecaptcha(self,user,channel,regchan=None):
		fname=""
		while len(fname)<5:
			fname=self.readable(os.urandom(128))[:8]+".html" #just a random file
			
		image = ImageCaptcha(fonts=["./arial.ttf"])
		code=""
		while len(code)<8:
			code=self.readable(str(os.urandom(384)).encode('base64','strict'))[:8]
		data = image.generate(code)
		html='''<html>
		<head>
		<title> Please type this code in the same irc window that you received this link in.</title>
		<!-- might do javascript loading of the pic here -->
		</head>
		<body background=black>
		<img src="data:image/png;base64,'''+base64.b64encode(data.getvalue())+'''" />
		</body>
		</html>'''
		with open(self.client.captchapath+fname,"war+") as f:
			f.write(html)
		url=self.client.uriprefix+fname
		if not None is regchan:
			for u in self.users:
				if u.hostname.lower() == user.hostname.lower():
					u.captchapending.add(regchan)
		Timer(self.client.captchaage,self.invalidatecaptcha,args=[user,channel]).start()
		return url,code
		
	def checkcaptcha(self,user,msg):
		msg=n(clean(msg))
		logging.info( "Checking captcha code |"+user.captchacode.lower()+"| against message |"+msg.lower()+"|")
		if msg.lower().strip()== user.captchacode.lower().strip():
			#self.db.updateuser(user)
			logging.debug( "Good code!")
		#	self.io.send("PRIVMSG "+user.nickname+" :Your humanity is proven! You may now join and speak in ##hackers ,however you will need to wait one more minute before you can join.")
			return True
		return False
		
	def invalidatecaptcha(self,user,channel):
		
		for u in self.users:
			if u.nickname.lower() == user.nickname.lower():

				if u.status == "BORINGHUMAN":
					return
				elif u.status == "CAPTCHAGOOD":
					if "UNDERAGEQUIET" in channel.role:
						logging.info( "Unquieting user:"+u.nickname+" In channel "+channel.name)
						self.unquiet(u,channel)	
					elif "REGOVERFLOW" in channel.role:
						self.io.send("MODE "+channel.regchan+" +I *!*@"+u.hostname)
						self.io.send("INVITE "+u.nickname+" "+channel.regchan)
					elif "AUTOVOICE" in channel.role:
						self.io.send("MODE "+channel.name+" +v "+u.nickname)
						self.whitelist(u.hostname)
						self.io.send("PRIVMSG "+u.nickname+" :You can now speak in "+channel.name)
					u.status="BORINGHUMAN"
						
					return

				u.status="CAPTCHAFAIL"
				u.captchafails=u.captchafails+1
				u.captchacode=""
				if u.captchafails <= self.client.captchafails and not u.status == "BORINGHUMAN":
					self.io.send("PRIVMSG "+u.nickname+" :Hi,You have entered an invalid code. You have "+str(self.client.captchafails-u.captchafails)+" Tries left.")
					url,code=self.makecaptcha(u,channel)
					u.captchacode=code
					self.io.send("PRIVMSG "+u.nickname+" :Let's try this one more time, Link: "+url)
					self.io.send("PRIVMSG "+u.nickname+" :Please enter the code above here. This code will expire after one minute. It is not case-sensitive and there are only alphabets and numbers in the code.")
				elif "REGOVERFLOW" in channel.role:
					self.io.send("PRIVMSG "+u.nickname+" : Please consider registering your nickname with services, type '/msg nickserv help register'	Further instructions can be found here https://freenode.net/kb/answer/registration")
					break
				elif "AUTOVOICE" in channel.role:
					self.io.send("PRIVMSG "+u.nickname+" :I'm sorry but you have exhaused all tries,please wait for an OP to allow you to speak in "+channel.name+" . In the mean time, why don't you register your nickname and ask for a cloak in freenode? https://freenode.net/kb/answer/registration")	
				break	
				
				
	def twettybird(self):
		timeline=[]
		#time.sleep(30) #startup nap
		firstrun=True
		try:
			while gv.running:
				#time.sleep(600)
				try:
					logging.debug("Fetching timeline")
					t=self.twapi.GetHomeTimeline(count=100)
					if firstrun:
						firstrun=False
						#continue
					for entry in t:
						
						skip=False
						created_sec=entry.created_at_in_seconds
						stamp=time.strftime("%Y-%m-%d %H:%M:%S %Z",time.gmtime(created_sec))
						msg="[TWITTER "+stamp+"] @"+unidecode(entry.user.name)+": "+unidecode(entry.text)
						if len(entry.urls)>0:
							for u in entry.urls:
								msg=msg+' , '+unidecode(u.expanded_url)
						msg=unidecode(msg)
						msg=msg.replace("\r","")
						msg=msg.replace("\n","")
						msg=msg+" https://twitter.com/"+entry.user.screen_name+"/status/"+entry.id_str
						#msg=str(chr(3)+"11").encode('ascii')+msg
						for o in timeline:
							if o.user.name == entry.user.name and o.text == entry.text:
								skip=True
						if skip:
							#logging.debug("Twitter >> Skipping due to existing entry:"+msg)
							continue
						else:
							#self.f.write(msg+"\n")		
							#self.fh.write("<div id='entry' style='border: 1px solid white;'>"+htm.escape(msg)+"</div></br>\n")
							with open("/usr/share/nginx/www/threatintel/raw.txt","a+",0) as lf:
								lf.write(msg+"\n")
									
						for c in self.channels:
							tagmatch=False
							if c.tags:
								for tag in c.tags:
									if tag.lower() in msg.lower():
										tagmatch=True
							if tagmatch or "THREATINTEL" in c.role:
								if len(msg) < 400:
									self.io.send("PRIVMSG "+c.name+" :"+msg)			
								else:
									broken=textwrap.wrap(msg,400)
									i=0
									count=len(broken)
									for b in broken:
										if len(b)>0:
											self.io.send("PRIVMSG "+c.name+" :"+msg+" ("+str(i)+"/"+str(count-1)+")")	
							

						timeline.append(entry)
						if len(timeline)>10000:
							timeline.remove(timeline[0])
					time.sleep(600)
				except Exception as e:
					logging.exception("Twitter exception!")
					time.sleep(1800)
					continue	
		finally:
			self.f.close()
			self.fh.close()
			
	def getotx(self,since):
		try:
			pulses = self.otxapi.getsince(since)
		except:
			return
		newpulse=set()
		for p in pulses:
			ioc=''
			fname=self.readable(hashlib.sha256(unidecode(n(p["name"]))).hexdigest())+".json"
			stamp=''
			if "created" in p:
				stamp=p["created"]
			if "modified" in p:
				stamp=p["modified"]	
				
			msg= "[OTX "+unidecode(stamp)+"] Name: "+unidecode(n(p["name"]))+" // "+"TLP: "+unidecode(n(p["TLP"]))+" // Description: "+unidecode(n(p["description"]))+" // Refs.: "+unidecode(' , '.join(n(p["references"])))
	
			if len(p["indicators"])>0:
				ioc=" // IoC: "+self.client.uriprefix_threatintel+fname
			with open(self.client.threatpath+fname,"war+") as f:
				f.write(json.dumps(p["indicators"],indent=4,sort_keys=True)+"\n\n")
			msg=msg+ioc		
			newpulse.add(msg)
		return newpulse
		
	def aliens(self):
		pulses=[]
		
		time.sleep(60) #startup nap
		try:
			while gv.running:
				try:
					t=self.getotx((datetime.now() - timedelta(days=3)).isoformat())
							
					for entry in t:
						
						skip=False
						entry=entry.replace("\r","")
						entry=entry.replace("\n","")
						for o in pulses:
							if o[0:32] == entry[0:32]:
								skip=True
								break
						if skip:
							#logging.debug("OTX >> Skipping due to existing entry:"+msg)
							continue
						else:				
							logging.debug("NEW OTX ENTRY:"+entry)
							#self.f.write(entry+"\n\n")	
							#self.fh.write("<div id='entry' style='border: 1px solid white;'>"+htm.escape(entry)+"</div></br>\n")
							with open("/usr/share/nginx/www/threatintel/raw.txt","a+",0) as lf:
								lf.write(entry+"\n\n")
								
						for c in self.channels:
							if tagmatch or ("THREATINTEL" in c.role and skip==False):
								if len(entry)>400:
									broken=textwrap.wrap(entry,400)
									i=0
									count=len(broken)
									for b in broken:
										if len(b)>0:
											b=str(chr(3)+"9").encode('ascii')+b
											self.io.send("PRIVMSG "+c.name+" :"+b+" ("+str(i)+"/"+str(count-1)+")")			
											i=i+1
								else:
									entry=str(chr(3)+"9").encode('ascii')+entry		
									self.io.send("PRIVMSG "+c.name+" :"+entry)			

						if skip==False:
							pulses.append(entry)
							if len(pulses)>10000:
								pulses.remove(pulses[0])

							#self.f.write(entry+"\n\n")	
							#self.fh.write("<div id='entry' style='border: 1px solid white;'>"+htm.escape(entry)+"</div></br>\n")
					time.sleep(1800)
				except Exception as e:
					logging.exception("OTX exception!")
					continue	
				time.sleep(600)
					
		finally:
			self.f.close()
			self.fh.close()	
			
	def breakup(self,string,limit):
		brokenup=[]
		if len(string)<limit:
			brokenup.append(string)
		else:
			pieces=len(string)/limit
			for i in range(pieces):
				brokenup.append(string[i*pieces:(i*pieces)+limit])
		return brokenup


							
	def user_input(self):
		while gv.running:
			try:


				usrmsg=raw_input(">")
				if usrmsg=="/QUIT":
					self.io.send("QUIT")
					gv.running=False
					sys.exit(0)
					return
				elif "users" in usrmsg.lower() :
					for u in self.users:
						print u.hostmask
				elif "channels" in usrmsg.lower() :
					for c in self.channels:
						print c.name
				else:		
					self.io.send(usrmsg)
			except Exception as e:
				logging.exception( "user_input exception,won't be able to accept interactive user input.")
				
				return
				
	def every5s(self):
		while gv.running:
			time.sleep(5)
			for c in self.channels:
				c.jt5s=0
				
	def every1m(self):
		while gv.running:
			time.sleep(60)
			for c in self.channels:
				c.jt1m=0
				
	def every5m(self):
		while gv.running:
			time.sleep(300)
			for c in self.channels:
				c.jt5m=0
				
	def every10m(self):
		while gv.running:
			time.sleep(600)
			for c in self.channels:
				c.jt10m=0
				
	def every30m(self):
		while gv.running:
			time.sleep(1800)
			for c in self.channels:
				c.jt30m=0
																			
	def quiet(self,user,channel,notify=False):
		if user.nickname.lower() == self.client.nick.lower():
			print "Not quieting myself!! haha wee"
			return
		mask="*!*@"+user.hostname
		self.io.send("MODE "+channel.name+" -v "+mask)
		self.io.send("MODE "+channel.name+" +q "+mask)
		self.blacklist(user.hostname)
		if not notify==True:
			return
		#self.io.send("PRIVMSG "+user.nickname+" :Greetings,You have been quieted in "+channel.name+". if this was by mistake, channel Operators have been notified and will change this.")
		
	def quietnick(self,uname,cname,notify=False):
		if uname.lower() == self.client.nick.lower():
			print "Not quieting myelf!! haha wee"
			return
		mask=uname+"!*@*"
		self.io.send("MODE "+cname+" +q "+mask)
		self.io.send("MODE "+cname+" -v "+mask)
		
		if not notify==True:
			return
		
		self.io.send("PRIVMSG "+uname+" :Greetings,You have been quieted in "+cname+". if this was by mistake, channel Operators have been notified and will change this.")
			
	def unquiet(self,user,channel):
		mask="*!*@"+user.hostname
		self.io.send("MODE "+channel.name+" +v "+mask)
		self.io.send("MODE "+channel.name+" -q "+mask)
		self.io.send("PRIVMSG "+user.nickname+" :You have been unquieted in "+channel.name+". Thank you for being part of our community at "+channel.name)
		self.io.send("PRIVMSG "+user.nickname+" :If you have trouble speaking please rejoin the channel('/part' followed by '/join "+channel.name+"') Have a great day!")
	def dbsync(self):
		now=time.time()
		if (now-self.lastsync) < 300:
			return
		#for u in self.users:
			#self.db.updateuser(u)
		#for c in self.channels:
			#self.db.updatechannel(c)
		self.lastsync=time.time()
		logging.info( "SYNC:"+str(self.lastsync))	


def main():


	gv.running=True
	threads=[]
	client=SimpleClient()
	client.handle_args(sys.argv)
	
	logging.basicConfig(filename="./debug-"+client.server+".log",level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
	logging.info( "Starting...")
	
	io=IO(client.connect_tls())
	io.start_threads()
	bot=Eye_Argh_See(client,io)
	
	bot_thread = Thread(target=bot.startme)
	bot_thread.daemon = False
	threads.append(bot_thread)
	bot_thread.start()
	
	twitter_thread = Thread(target=bot.twettybird)
	twitter_thread.daemon = False
	threads.append(twitter_thread)
	twitter_thread.start()
	
#	otx_thread = Thread(target=bot.aliens)
#	otx_thread.daemon = False
#	threads.append(otx_thread)
#	otx_thread.start()
	
	every5s_thread = Thread(target=bot.every5s)
	every5s_thread.daemon = False
	threads.append(every5s_thread)
	every5s_thread.start()
	
	every1m_thread = Thread(target=bot.every1m)
	every1m_thread.daemon = False
	threads.append(every1m_thread)
	every1m_thread.start()
	
	every5m_thread = Thread(target=bot.every5m)
	every5m_thread.daemon = False
	threads.append(every5m_thread)
	every5m_thread.start()
	
	every10m_thread = Thread(target=bot.every10m)
	every10m_thread.daemon = False
	threads.append(every10m_thread)
	every10m_thread.start()
	
	every30m_thread = Thread(target=bot.every30m)
	every30m_thread.daemon = False
	threads.append(every30m_thread)
	every30m_thread.start()
	
	
		
	input_thread = Thread(target=bot.user_input)
	input_thread.daemon=False
	threads.append(input_thread)
	input_thread.start()

	while gv.running:
		time.sleep(1)

	
	os._exit(0)	
		
	print "Exiting."
	
if __name__ == "__main__":
	main()

