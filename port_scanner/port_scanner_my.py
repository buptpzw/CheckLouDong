# -*- coding = utf-8 -*-

import socket

def port_scanner(ip):
    s = socket.socket()
    ports = [8080,8081,9080,80,1080,21,23,443,69,22,25,110,9090,2100]
    port_open = []
    #for p in range(65535):
    for p in ports:
        try:
            s.connect((ip, p))
            s.send("Primal Security \n")
            reponse = s.recv(1024)
            if reponse:
                str1 = "[+] Port "+str(p)+" open"
                print "[+] Port "+str(p)+" open: "+reponse
                port_open.append(str1)
        except Exception:
            pass
    s.close()
    return port_open

if __name__ == "__main__":
    #ip = "10.18.33.120"
    ip = "61.135.169.121"
    port_open = port_scanner(ip)
    print port_open

