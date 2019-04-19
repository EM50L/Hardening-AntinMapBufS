#!/usr/bin/python
import os
print 'Antinmap detecta y bannea(bloquea) ips que intentan escanear este servidor.' #puertos registrados 1-49151

filtro_pcap  = '"inbound and dst portrange 1-31000 and dst port not 22 and dst port not 80 and dst port not 443 and dst port not 10519"'
#filtro_pcap = '"ip and inbound and (dst portrange 1-79 or dst portrange 81-442 or dst portrange 444-27300)"'
nips         = 256
buffer_ips   = [None for i in xrange(nips)]
lista_blanca = ['8.8.8.8','1.1.1.1','10.8.0.19']
cmd_banip    = 'iptables -A INPUT -j DROP -s ' #+ip_mala  # -A append pongo la regla al final
#cmd_banip    = 'iptables -I INPUT 6 -j DROP -s '#+ip_mala  # -I 6 en algunos sistemas hay que insertar las reglas al principio linea 6
cmd_unbanip  = 'iptables -D INPUT -j DROP -s ' #desbloqueo IP
#debug: print 'tcpdump -c1 -nn -l -s64 '+filtro_pcap

while True:
    tcpdump=os.popen('tcpdump -c1 -nn -l -s64 '+filtro_pcap+' 2>/dev/null').read()
    #debug: print tcpdump #tcpdump contiene la informacion en bruto del paquete capturado

    try:
    	ip_mala=tcpdump.split(' ')[2].split('.') #la ip esta en la 3palabra[2] desde el principio
    	ip_mala=ip_mala[0]+"."+ip_mala[1]+"."+ip_mala[2]+"."+ip_mala[3] #recompongo(quitando ultimo bloque .XXXX)
    	puerto = tcpdump.split('.')[9].split(']')[0].replace(' ','').replace('Flags[','').replace('|','')[:15]
	print "\nip :",ip_mala,"puerto:",puerto

	if ip_mala in lista_blanca: continue #si la ip esta autorizada continua sin bannearla
	if ip_mala in buffer_ips:   continue #si la ip ya esta banneada continuo

	print "ip_mala:",ip_mala,"puerto:",puerto,"  ",tcpdump
	buffer_ips.append(ip_mala)
	os.system( cmd_banip + ip_mala )

    	ip_out = buffer_ips.pop(0) # saco ip mas antigua del buffer
    	if (ip_out != None):
	    print "Lista llena saco una ip: ip_out=",ip_out 
	    os.system( cmd_unbanip + ip_out ) #desbloqueo IP

    except Exception as e:  #except:
    	print "Ups algo a pasado(error)! ",e,"\ntcpdump:",tcpdump
print 'Fin programa!'
