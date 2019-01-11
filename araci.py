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
liste = {UUID: [UUID, ip, str(port), "A", nickname]}

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

print("liste:")
for i in liste:
	print("  ", liste[i])

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
			f.write(str(time.ctime()) + " - " + str(msg) + '\r\n')		#print yerine dosyaya yaz.
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


def soketeYaz(c, text):
	sleep(0.05)
	c.send((text+"\r\n").encode())
	logQueue.put(text + " gonderildi")	#print yerine logger threade yollanacak


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

			else:
				soketeYaz(self.c, "ERSY")

		self.c.close()
		print("baglanti kapatildi")
		logQueue.put("baglanti kapatildi")


queueLock = threading.Lock()
threads = []
threadID = 1
logQueue = queue.Queue()

s = socket.socket()  # Create a socket object
host = "0.0.0.0"  # Accesible by all of the network


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


