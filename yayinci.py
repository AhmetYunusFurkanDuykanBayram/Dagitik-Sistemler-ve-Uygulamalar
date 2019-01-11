import queue
import threading
import time
import socket
from uuid import getnode as get_mac
from pathlib import Path 
from time import sleep
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from os import listdir
import random

#UUID = get_mac()
ExitFlag = False

UUID_file = Path("UUID.txt")
#Eger daha once UUID olusturulmussa
if UUID_file.is_file():
	f = open("UUID.txt", "r")
	f2 = open("port.txt", "r")
	f3 = open("nickname.txt", "r")
	UUID = f.read()
	port = int(f2.read())
	nickname = f3.read()
	f.close();
	f2.close();
	f3.close();
#Degilse yeni olusturulani dosyaya yaz
else:
	nickname = input("Nickname Giriniz: ")
	#Yeni UUID olusturma
	UUID = int(random.random()*10000)
	UUID = str(UUID)
	#server icin port (2000-65500)
	port = int(random.random()*63500)+2000
	f = open("UUID.txt", "w")
	f2 = open("port.txt", "w")
	f3 = open("nickname.txt", "w")
	f.write(UUID)
	f2.write(str(port))
	f3.write(nickname)
	f.close();
	f2.close();
	f3.close();
	
#ip adresini ogrenme
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip = s.getsockname()[0]
buf_size = 2048

#listeler ve dictionary'ler
liste = {UUID: [UUID, ip, str(port), "Y", nickname]}
bloklist = [] 		#UUID
publickeylist = []	#[UUID, publickey]
following = []		#UUID
followers = []		#UUID
mikroblogs = []		#string



liste_file = Path("liste.txt")
if liste_file.is_file():
	f = open("liste.txt", "r")
	txt = f.read()
	f.close();
	ls = txt.split('\n')
	while True:
		try:
			ls.remove('')
		except:
			break
	for i in ls:
		j = i.split(', ')
		liste[j[0]] = j

else:
	f = open("liste.txt", "w")
	f.write(liste[UUID][0] + ", " + liste[UUID][1] + ", " + liste[UUID][2] + ", " + liste[UUID][3] + ", " + liste[UUID][4] + '\r\n')
	f.close();


following_file = Path("following.txt")
if following_file.is_file():
	f = open("following.txt", "r")
	txt = f.read()
	following = txt.split('\n')
	while True:
		try:
			following.remove('')
		except:
			break
	f.close();
else:
	f = open("following.txt", "w")
	f.close();


followers_file = Path("followers.txt")
if followers_file.is_file():
	f = open("followers.txt", "r")
	txt = f.read()
	followers = txt.split('\n')
	while True:
		try:
			followers.remove('')
		except:
			break
	f.close();
else:
	f = open("followers.txt", "w")
	f.close();

bloklist_file = Path("bloklist.txt")
if bloklist_file.is_file():
	f = open("bloklist.txt", "r")
	txt = f.read()
	bloklist = txt.split('\n')
	while True:
		try:
			bloklist.remove('')
		except:
			break
	f.close();
else:
	f = open("bloklist.txt", "w")
	f.close();


#Varsa eski publickey listesini cekme
for filename in listdir():
	if(filename[-4:]==".pub"):
		f = open(filename, "r")
		key = RSA.importKey(f.read())
		publickeylist.append([filename[:-4],key.exportKey().decode()])


cast_file = Path("cast.txt")
if cast_file.is_file():
	f = open("cast.txt", "r")
	txt = f.read()
	mikroblogs = txt.split('\n')
	while True:
		try:
			mikroblogs.remove('')
		except:
			break
	f.close();
else:
	f = open("cast.txt", "w")
	f.close();

pub_file = Path("id_rsa_pub.txt")
pri_file = Path("id_rsa_pri.txt")	
if pub_file.is_file() and pri_file.is_file():
	f_pub = open("id_rsa_pub.txt", "r")
	f_pri = open("id_rsa_pri.txt", "r")
	public_key = RSA.importKey(f_pub.read())
	private_key = RSA.importKey(f_pri.read())
else: 
	random_generator = Random.new().read
	new_key = RSA.generate(2048, randfunc=random_generator)
	public_key = new_key.publickey()
	private_key = new_key
	f = open('id_rsa_pri.txt','w')
	f.write(private_key.exportKey().decode())
	f.close()
	f = open('id_rsa_pub.txt','w')
	f.write(public_key.exportKey().decode())
	f.close()


log_file = Path("log.txt")
if not log_file.is_file():
	f = open("log.txt", "w")
	f.close();


class loggerThread (threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		f = open("log.txt", "a")
		f.write(str(time.ctime()) + " - " + "Starting." + '\r\n')
		f.close();
		
		while True:
			try:
				msg = logQueue.get()
			except:
				msg = "QUIT"
			if msg == "QUIT":
				f = open("log.txt", "a")
				f.write(str(time.ctime()) + " - " + "QUIT received." + '\r\n')
				f.close();
				break
			f = open("log.txt", "a")
			f.write(str(time.ctime()) + " - " + str(msg) + '\r\n')
			f.close();
		f = open("log.txt", "a")
		f.write(str(time.ctime()) + " - " + "Exiting." + '\r\n')
		f.close();

def parser(data):
	if "\r\n" in data:
		data = data[:-2]
	elif "\n" in data:
		data = data[:-1]
	komut = data[:4]
	icerik = data[5:]
	list = icerik.split(", ")
	if komut == "ERSY" or komut == "ERLO" or komut == "ERKY":
		print(komut)
	return komut, list

def client_parser(data):
	if "\r\n" in data:
		data = data[:-2]
	elif "\n" in data:
		data = data[:-1]
	komut = data[:4]
	icerik = data[5:]
	return komut, icerik

def soketeYaz(c, text):
	sleep(0.05)
	c.send((text+"\r\n").encode())
	logQueue.put(text + " gonderildi")


class serverThread(threading.Thread):
	def __init__(self, c, addr):
		threading.Thread.__init__(self)
		self.c = c
		self.addr = addr
		
	def run(self):
		UUID_C = None
		accepted = False
		while True:
			ERSY = False
			try:
				data = self.c.recv(buf_size).decode()
				if len(data) == 0:	#karsi taraf Ctrl C ile kapatirsa bos string okuyor
					break
				logQueue.put(data[:-2] + " alindi")
				
			except:
				break
			komut, icerik = parser(data)
			
			if komut=="ESCN":
				try:
					UUID_C = icerik[0]
					adres = icerik[1]
					port = icerik[2]
					type = icerik[3]
					nickname = icerik[4]
				except:
					soketeYaz(self.c, "ERSY")
					ERSY = True
				
				if not ERSY:	#syntax hatasi yoksa
					soketeYaz(self.c, "WAIT")
					try:
						tmp = liste[UUID_C]
					except:
						tmp=["","","","",""]
					if tmp[0] == icerik[0] and tmp[1] == icerik[1] and tmp[2] == icerik[2]:
						soketeYaz(self.c, "ACCT")
						accepted = True
					else:
						try:
							s = socket.socket()
							s.connect((adres,int(port)))
							soketeYaz(s, "WHOU")
							data = s.recv(buf_size).decode()
							logQueue.put(data[:-2] + " alindi")
							s.close()
							
							komut, icerik2 = parser(data)
							if komut == "MYID":
								if icerik2[0] == UUID_C:
									soketeYaz(self.c, "ACCT")
									accepted = True
									liste[UUID_C]=icerik	#listeye ekleme
									f = open("liste.txt", "a")
									f.write(liste[UUID_C][0] + ", " + liste[UUID_C][1] + ", " + liste[UUID_C][2] + ", " + liste[UUID_C][3] + ", " + liste[UUID_C][4] + '\r\n')
									f.close()
								else:
									soketeYaz(self.c, "REJT")
						except:
							soketeYaz(self.c, "REJT")
			elif komut == "WHOU":
				soketeYaz(self.c, "MYID " + str(UUID))
			elif not accepted:
				soketeYaz(self.c, "ERLO")
			elif komut == "LIST" and len(icerik)==1:
				size = 0
				if icerik[0] == "all":
					size = len(liste)
				else:
					try:
						size = int(icerik[0])
					except:
						soketeYaz(self.c, "ERSY int")	#int bir deger degilse
						continue
				
				for l in liste:
					if size <=0:
						break
					soketeYaz(self.c, "LSIS " + liste[l][0] + ", " + liste[l][1] + ", " + liste[l][2] + ", " + liste[l][3] + ", " + liste[l][4])
					size = size-1
				soketeYaz(self.c, "LSIS")
# yayıncı
			elif komut == "SUBS":
				pub_list_cont = False
				for i in publickeylist:
					if i[0] == UUID_C:
						pub_list_cont = True
						break
				if UUID_C in bloklist:
					soketeYaz(self.c, "BLOK")
				elif not pub_list_cont:
					soketeYaz(self.c, "ERKY")
				else:
					if not UUID_C in followers:
						f = open("followers.txt", "a")
						f.write(UUID_C+'\r\n')
						f.close()
						followers.append(UUID_C)
					soketeYaz(self.c, "SUBA")
			elif komut == "UNSB":
				try:
					followers.remove(UUID_C)
					f = open("followers.txt", "w")
					for fol in followers:
						f.write(fol+'\r\n')
					f.close()
				except:
					pass
				soketeYaz(self.c, "UNSA")
			elif komut == "UNBL":
				soketeYaz(self.c, "UNBA")
			elif komut == "KYRQ":
				publickeylist.append([UUID_C,icerik[0]])
				f = open(UUID_C+".pub", "w")
				f.write(icerik[0]+".pub")
				f.close()
				res = "MYKY " + public_key.exportKey().decode()
				soketeYaz(self.c, res)
			elif komut == "KYCO":
				pub_list_cont = False
				for i in publickeylist:
					if i[0] == UUID_C:
						pub_list_cont = True
						break
				if not pub_list_cont:
					soketeYaz(self.c, "ERKY")
				else:
					text = 'abcdefgh'
					hash = SHA256.new(text.encode()).digest()
					imza = private_key.sign(hash, "")
					soketeYaz(self.c, "SIGN " + str(imza[0]) + ", " + text)
			elif komut == "CAST":
				mb = (self.c.recv(buf_size),)
				print(liste[UUID_C][4]+" mikroblog atti:",private_key.decrypt(mb).decode())
				logQueue.put(liste[UUID_C][4]+" mikroblog atti: " + private_key.decrypt(mb).decode())
				soketeYaz(self.c, "CSTA")
			elif komut == "MBRQ":
				try:
					num = int(icerik[0])
				except:
					soketeYaz(self.c, "ERSY")
					continue
				pub_list_cont = False
				for i in publickeylist:
					if i[0] == UUID_C:
						pub_list_cont = True
						break
				if UUID_C in bloklist:
					soketeYaz(self.c, "BLOK")
				elif not pub_list_cont:
					soketeYaz(self.c, "ERKY")
				else:
					num_tmp = num
					soketeYaz(self.c,"MBLG")
					for p in publickeylist:
						if p[0] == UUID_C:

							for mb in reversed(mikroblogs):
								if num <=0:
									break
								self.c.send(RSA.importKey(p[1]).encrypt((str(num_tmp-num) + ' ' + mb).encode(), 1024)[0])
								logQueue.put(RSA.importKey(p[1]).encrypt((str(num_tmp-num) + ' ' + mb).encode(), 1024)[0])
								sleep(0.05)
								num = num - 1
							self.c.send(RSA.importKey(p[1]).encrypt(str(-1).encode(), 1024)[0])
							logQueue.put("-1 gonderildi")
							sleep(0.05)
							break
			elif komut == "MESG":
				pub_list_cont = False
				for i in publickeylist:
					if i[0] == UUID_C:
						pub_list_cont = True
						break
				if UUID_C in bloklist:
					soketeYaz(self.c, "BLOK")
				elif not pub_list_cont:
					soketeYaz(self.c, "ERKY")
				else:
					soketeYaz(self.c, "MSGA")
					ozel_mesaj = (self.c.recv(buf_size),)
					print(liste[UUID_C][4]+" ozel mesaj atti:",private_key.decrypt(ozel_mesaj).decode())
					logQueue.put(liste[UUID_C][4] + " ozel mesaj atti: " + private_key.decrypt(ozel_mesaj).decode())
			else:
				soketeYaz(self.c, "ERSY")

		self.c.close()
		print("baglanti kapatildi")
		logQueue.put("baglanti kapatildi")


class baglantiKurucu(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
	
	def run(self):
		while not ExitFlag:
			print("liste:")
			for i in liste:
				print("  ", liste[i])
			print("takip edilenler:")
			for i in following:
				print("  ",i)
			print("takipciler:")
			for i in followers:
				print("  ",i)
			print("bloklular:")
			for i in bloklist:
				print("  ",i)
			print("mikrobloglarim:")
			for i in reversed(mikroblogs):
				print("  ",i)
			try:
				tmp = input()	#CAST <mesaj> | ...
			except:
				break
			secenek = tmp.split(" ")
			if secenek[0] == "CAST":
				f = open("cast.txt", "a")
				f.write(tmp[5:]+'\r\n')
				f.close()
				mikroblogs.append(tmp[5:])
				for i in followers:
					if i in bloklist:
						continue
					s=socket.socket()
					s.connect((liste[i][1], int(liste[i][2])))
					soketeYaz(s,"ESCN " + liste[str(UUID)][0] + ", " + liste[str(UUID)][1] + ", " + liste[str(UUID)][2] + ", " + liste[str(UUID)][3] + ", " + liste[str(UUID)][4])
					k, sec = parser(s.recv(buf_size).decode())	#WAIT al
					logQueue.put(k+" alindi")
					k, sec = parser(s.recv(buf_size).decode())
					logQueue.put(k+" alindi")
					if k == "ACCT":
						for p in publickeylist:
							if p[0] == i:
								soketeYaz(s,"CAST")
								s.send(RSA.importKey(p[1]).encrypt(tmp[5:].encode(), 1024)[0])
								logQueue.put(RSA.importKey(p[1]).encrypt(tmp[5:].encode(), 1024)[0])
								k, sec = parser(s.recv(buf_size).decode())	#CSTA al
								logQueue.put(k+" alindi")
								break
					s.close()
		
			elif secenek[0] == "con":
				s=socket.socket()
				try:
					s.connect((secenek[1], int(secenek[2])))
				except:
					continue
				UUID_S = None
			elif secenek[0] == "con2":
				connection_control = False
				s=socket.socket()
				for i in liste:
					if liste[i][4] == tmp[5:]:
						UUID_S = liste[i][0]
						connection_control = True
						break
				if not connection_control:
					UUID_S = None
					continue
				try:
					s.connect((liste[UUID_S][1], int(liste[UUID_S][2])))
				except:
					UUID_S = None
					continue

##
			if secenek[0] == "con" or secenek[0] == "con2":
				while not ExitFlag:
					try:
						msg = input()
					except:
						break
					cmd, con = client_parser(msg)
					if cmd == "chus":
						break
					if cmd == "UNSB":
						try:
							following.remove(UUID_S)
							f = open("following.txt", "w")
							for fol in following:
								f.write(fol+'\r\n')
							f.close()
						except:
							pass
					elif cmd == "BLOK":
						if UUID_S is None:
							pass
						else:
							f = open("bloklist.txt", "a")
							f.write(UUID_S+'\r\n')
							f.close()
							bloklist.append(UUID_S)
							continue
					elif cmd == "UNBL":
						if UUID_S is not None:
							try:
								bloklist.remove(UUID_S)
								f = open("bloklist.txt", "w")
								for bl in bloklist:
									f.write(bl+'\r\n')
								f.close()
							except:
								pass
					elif cmd == "DISP":
						for i in liste:
							print(liste[i])
						continue
					elif cmd == "KYRQ":
						msg = "KYRQ " + public_key.exportKey().decode()
					elif cmd == "ESCN":
						msg = "ESCN " + liste[str(UUID)][0] + ", " + liste[str(UUID)][1] + ", " + liste[str(UUID)][2] + ", " + liste[str(UUID)][3] + ", " + liste[str(UUID)][4]
					elif cmd == "LIST" and con != "all":
						try:
							if int(con) <= 0:
								print("ERSY")
								logQueue.put("ERSY alindi")
								continue
						except:
							print("ERSY")
							logQueue.put("ERSY alindi")
							continue
					elif cmd == "MESG":
						soketeYaz(s, "MESG")
						mesg_cevabi, mesg_cevabi2 = parser(s.recv(buf_size).decode())
						logQueue.put(mesg_cevabi + " alindi")
						if mesg_cevabi == "MSGA":
							for p in publickeylist:
								if p[0] == UUID_S:
									s.send(RSA.importKey(p[1]).encrypt(con.encode(), 1024)[0])
									logQueue.put(RSA.importKey(p[1]).encrypt(con.encode(), 1024)[0])
									break
						else:
							print(mesg_cevabi)
							
						continue
					elif cmd == "CAST":
						s.close()
						f = open("cast.txt", "a")
						f.write(con+'\r\n')
						f.close()
						mikroblogs.append(con)
						for i in followers:
							if i in bloklist:
								continue
							s_cast=socket.socket()
							s_cast.connect((liste[i][1], int(liste[i][2])))
							soketeYaz(s_cast,"ESCN " + liste[str(UUID)][0] + ", " + liste[str(UUID)][1] + ", " + liste[str(UUID)][2] + ", " + liste[str(UUID)][3] + ", " + liste[str(UUID)][4])
							k, sec = parser(s_cast.recv(buf_size).decode())	#WAIT al
							logQueue.put(k+" alindi")
							k, sec = parser(s_cast.recv(buf_size).decode())
							logQueue.put(k+" alindi")
							if k == "ACCT":
								for p in publickeylist:
									if p[0] == i:
										soketeYaz(s_cast,"CAST")
										s_cast.send(RSA.importKey(p[1]).encrypt(con.encode(), 1024)[0])
										logQueue.put(RSA.importKey(p[1]).encrypt(con.encode(), 1024)[0])
										k, sec = parser(s_cast.recv(buf_size).decode())	#CSTA al
										logQueue.put(k+" alindi")
										break
							s_cast.close()
						break
		###
					try:
						soketeYaz(s,msg)
					except:
						break
					try:
						data = s.recv(buf_size).decode()
					except:
						break
					komut, icerik = parser(data)
					if komut == "":
						break
					logQueue.put(data[:-2]+" alindi")
					if komut == "WAIT":
						data = s.recv(buf_size).decode()
						komut, icerik = parser(data)
						logQueue.put(data[:-2]+" alindi")
						if komut == "ACCT" and UUID_S == None:
							soketeYaz(s,"WHOU")
							data = s.recv(buf_size).decode()
							logQueue.put(data[:-2]+" alindi")
							komut, icerik = parser(data)
							UUID_S = icerik[0]
							print("UUID_S:", UUID_S)
					elif komut == "LSIS":
						f = open("liste.txt", "a")
						if len(icerik[0])== 0:	# liste tamamen alindi
							f.close()
							continue
						liste[icerik[0]] = icerik
						f.write(liste[icerik[0]][0] + ", " + liste[icerik[0]][1] + ", " + liste[icerik[0]][2] + ", " + liste[icerik[0]][3] + ", " + liste[icerik[0]][4] + '\r\n')
						while komut == "LSIS":
							data = s.recv(buf_size).decode()
							logQueue.put(data[:-2]+" alindi")
							komut, icerik = parser(data)
							if len(icerik[0])== 0:	# liste tamamen alindi
								f.close()
								break
							liste[icerik[0]] = icerik
							f.write(liste[icerik[0]][0] + ", " + liste[icerik[0]][1] + ", " + liste[icerik[0]][2] + ", " + liste[icerik[0]][3] + ", " + liste[icerik[0]][4] + '\r\n')
					elif komut == "MYKY":
						publickeylist.append([UUID_S, icerik[0]])
						f = open(UUID_S+".pub", "w")
						f.write(icerik[0])
						f.close()
					elif komut == "SIGN":
						sig = (int(icerik[0]),)
						text = icerik[1]
						hash = SHA256.new(text.encode()).digest()
						for i in publickeylist:
							if UUID_S == i[0]:
								print(i)
								public_key_s = RSA.importKey(i[1])
								break
						print(public_key_s.verify(hash, sig))
					elif komut == "SUBA":
						if not UUID_S in following:
							f = open("following.txt", "a")
							f.write(UUID_S+'\r\n')
							f.close()
							following.append(UUID_S)
					elif komut == "MBLG":
						while True:
							mb = private_key.decrypt((s.recv(buf_size),)).decode()
							if mb[:2] == '-1':
								logQueue.put("-1 alindi")
								break
							mb = mb[mb.index(' ')+1:]
							print("migroblog",mb)
							logQueue.put("migroblog " + mb + " alindi")
					
				s.close()


queueLock = threading.Lock()
threads = []
threadID = 1
logQueue = queue.Queue()

s = socket.socket()  # Create a socket object
host = "0.0.0.0"  # Accesible by all of the network

thread = baglantiKurucu()
thread.start()

thread = loggerThread()
thread.start()


try:
	s.bind((host, port))  # Bind to the port
except Exception as e:
	port = int(input(str(e) + "\n" + str(port) + " Portu kapanmamis, yeni port giriniz: "))
	s.bind((host, port))

s.listen(5)  # Now wait for client connection,
# with 5 queued connections at most


while True:
	try:
		c, addr = s.accept()
	except:
		s.close()
		print("QUIT received.")
		ExitFlag = True
		break
	
	thread = serverThread(c,addr)
	thread.start()


