class baglantiKurucu(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
	
	def run(self):
		tmp = input("adres port: ").split(" ")
		s=socket.socket()
		s.connect((tmp[0], int(tmp[1])))
		while True:
			try:
				soketeYaz(s,input())
			except:
				break
			try:
				data = s.recv(1024).decode()
			except:
				break
			komut, icerik = parser(data)
			if komut == "":
				break
			print(komut)
			if komut == "WAIT":
				data = s.recv(1024).decode()
				komut, icerik = parser(data)
				print(komut)