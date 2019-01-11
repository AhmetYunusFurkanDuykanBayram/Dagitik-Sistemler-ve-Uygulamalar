import queue
import threading
import time
import socket
from uuid import getnode as get_mac
from pathlib import Path 

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256ü

UUID = get_mac()
ExitFlag = False
UUID = 12

pub_file = Path(UUID + "id_rsa.txt")
pri_file = Path(UUID + "id_rsa_pub.txt")

if pub_file.is_file() and pri_file.is_file():
	f_pub = open(UUID + "id_rsa.txt", "r")
	f_pri = open(UUID + "id_rsa_pub.txt", "r")
	public_key = RSA.importKey(f_pub.read())
	private_key = RSA.importKey(f_pri.read())
else: 
	random_generator = Random.new().read
	new_key = RSA.generate(2048, randfunc=random_generator)
	public_key = new_key.publickey()
	private_key = new_key
	f = open(UUID + 'id_rsa_pri.txt','w')
	f.write(private_key.exportKey().decode())
	f.close()
	f = open(UUID + 'id_rsa_pub.txt','w')
	f.write(public_key.exportKey().decode())
	f.close()

liste = {str(UUID): [str(UUID), "192.168.0.14", "2000", "A", "araci2"]}
bloklist = [] 		# 
publickeylist = []	#[uuid, publickey]
sublist = []		

def parser(data):
	if "\r\n" in data:
		data = data[:-2]
	elif "\n" in data:
		data = data[:-1]
	komut = data[:4]
	icerik = data[5:]
	list = icerik.split(", ")
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
	c.send((text+"\r\n").encode())
	print(text,"gonderildi")

class serverThread(threading.Thread):
	def __init__(self, c, addr):
		threading.Thread.__init__(self)
		self.c = c
		self.addr = addr
		
	def run(self):
		UUID_C = None
		accespted = False
		while True:
			ERSY = False
			try:
				data = self.c.recv(1024).decode()
				if len(data) == 0:	#karsi taraf Ctrl C ile kapatirsa bos string okuyor
					break
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
				
				if not ERSY:
					soketeYaz(self.c, "WAIT")
					try:
						tmp = liste[UUID_C]
					except:
						tmp=["","","","",""]
					if tmp[0] == icerik[0] and tmp[1] == icerik[1] and tmp[2] == icerik[2]:
						soketeYaz(self.c, "ACCT")
						accespted = True
					else:
						try:
							s = socket.socket()
							s.connect((adres,int(port)))
							soketeYaz(s, "WHOU")
							data = s.recv(1024).decode()
							print(data)
							s.close()
							
							komut, icerik2 = parser(data)
							if komut == "MYID":
								if icerik2[0] == UUID_C:
									soketeYaz(self.c, "ACCT")
									accespted = True
									liste[UUID_C]=icerik	#listeye ekleme
								else:
									soketeYaz(self.c, "REJT")
						except:
							soketeYaz(self.c, "REJT")
			elif komut == "WHOU":
				soketeYaz(self.c, "MYID " + str(UUID))
			elif not accespted:
				soketeYaz(self.c, "ERLO")
			elif komut == "LIST" and len(icerik)==1:
				size = 0
				if icerik[0] == "all":
					size = len(liste)
				else:
					try:
						size = int(icerik[0])
					except:
						soketeYaz(self.c, "ERSY")	#int bir deger degilse
				
				for l in liste:
					if size <=0:
						break
					soketeYaz(self.c, "LSIS " + liste[l][0] + ", " + liste[l][1] + ", " + liste[l][2] + ", " + liste[l][3] + ", " + liste[l][4])
					size = size-1
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
					sublist.append(UUID_C)
					soketeYaz(self.c, "SUBA")
			elif komut == "UNSB":
					soketeYaz(self.c, "UNSA")
			else:
				soketeYaz(self.c, "ERSY")
		





		self.c.close()
		print("baglanti kapatildi")


class baglantiKurucu(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
	
	def run(self):
		tmp = input("adres port: ").split(" ")
		if int(tmp[1]) == 0:
			return
		s=socket.socket()
		s.connect((tmp[0], int(tmp[1])))

# önemli
		while True:		
			try:
				msg = input()
			except:
				pass
			



			cmd, con = client_parser(msg)					
			if cmd == "UNSB":
				try:
					sublist.remove(con)
				except:
					pass
###
			try:
				soketeYaz(s,msg)
			except:
				break
			try:
				data = s.recv(1024).decode()
			except:
				break
			komut, icerik = parser(data)
			if komut == "":
				break
			print(komut, icerik)
			if komut == "WAIT":
				data = s.recv(1024).decode()
				komut, icerik = parser(data)
				print(komut, icerik)
			else:
				while komut == "LSIS":
					data = s.recv(1024).decode()
					komut, icerik = parser(data)
					if len(icerik[0])== 0:	# liste tamamen alindi
						break
					print(komut, icerik)

queueLock = threading.Lock()
threads = []
threadID = 1
logQueue = queue.Queue()

s = socket.socket()  # Create a socket object
host = "0.0.0.0"  # Accesible by all of the network
port = 2005  # Reserve a port for your service.

thread = baglantiKurucu()
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


