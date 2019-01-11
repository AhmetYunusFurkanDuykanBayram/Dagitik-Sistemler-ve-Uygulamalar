import queue
import threading
import time
import socket
from uuid import getnode as get_mac
UUID = get_mac()

ExitFlag = False

liste = {str(UUID): [str(UUID), "192.168.0.14", "12345", "A", "araci1"]}


def parser(data):
	if "\r\n" in data:
		data = data[:-2]
	elif "\n" in data:
		data = data[:-1]
	komut = data[:4]
	icerik = data[5:]
	list = icerik.split(", ")
	return komut, list

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
	
			else:
				soketeYaz(self.c, "ERSY")
		self.c.close()
		print("baglanti kapatildi")


queueLock = threading.Lock()
threads = []
threadID = 1
logQueue = queue.Queue()

s = socket.socket()  # Create a socket object
host = "0.0.0.0"  # Accesible by all of the network
port = 12345  # Reserve a port for your service.

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


