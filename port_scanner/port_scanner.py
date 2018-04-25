# -*- coding=utf-8 -*-
from socket import *
import threading

lock = threading.Lock()
openNum = 0
threads = []

def portScanner(host,port, port_open = []):
    global openNum
    try:
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((host,port))
        lock.acquire()
        openNum+=1
        str1 = "[+] Port " + str(port) + " open"
        port_open.append(str1)
        lock.release()
        s.close()
    except:
        pass

def PortScannerThread(ip):
    setdefaulttimeout(1)
    #ip = input('please enter your host: ')
    #ip = "127.0.0.1"
    port_open = []
    for p in range(1,50000):
        t = threading.Thread(target=portScanner,args=(ip,p, port_open))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    str1 = '[+] The scan is complete!'
    port_open.append(str1)
    str2 = '[+] A total of %d open port ' % (openNum)
    port_open.append(str2)
    return port_open

if __name__ == '__main__':
    ip = "127.0.0.1"
    port_open = PortScannerThread(ip)
    print port_open
