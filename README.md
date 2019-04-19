# Hardening-AntinMapBufS


En este scritpt de solo **32 lineas** presento un antiNmap (Deteccion de Escaneos) que combinado con un Banneo (bloqueo de ip a nivel de cortafuegos). Nos va ha permitir parar/bloquear muchos ataques incluso antes de que se produzcan.

Hardening o endurecimiento es el proceso de asegurar un sistema reduciendo sus vulnerabilidades o agujeros de seguridad.

Explicacion: en el caso de los servidores una buena tactica de defensa es anticiparse a los ataques. Bloqueando al atacante incluso antes de que se inicie dicho ataque.

Como: casi todo ataque va precedido de una deteccion/escaner. 
En este caso usamos el comando **tcpdump** para detectar escaneos detectando y analizando todos los paquetes entrantes. despues de un filtro detecto toda actividad **anomala**. 

Ej: si una ip trata de conectarse al servicio VNC 
(si yo no tengo VNC que hace un parquete intentando conectarse.....) entonces obtengo la ip origen y se la paso al cortafuegos y la bloqueo.

La ventaja de este script respecto del AntinMap sencillo
es que bloquea por si solo las ips Atacantes (sin necesidad de terceros programas).
Para ello implemente un buffer (para no saturar la memoria del cortafuegos) y voy bloqueando las ips atacantes.

Este script dada su sencillez lo he licenciado bajo Licencia MIT (la mas permisiva) Luego podras usarlo , modificarlo incluso a nivel privado.

https://es.wikipedia.org/wiki/Licencia_MIT

https://choosealicense.com/licenses/mit/

Estadisticas reales de los bloqueos realizados por el script en 5VPS
(ver http://node.jejo.pw/honeymap).

![](./Estadisticas_AntiNmapBuffS.jpg)

En el momento de la captura el Antinmap ha bloqueado **175 000 ataques** 

Luego este sistema bloquea bloquea por si solo el **95%** de los ataques.

Estoy preparando una version mas elaborada en la que
alarga el tiempo de bloqueo de las ips que atacan varias veces a la maquina.
Ademas de implementar bloqueo por zona. (si el atacante cambia de ip le seguira bloqueando)

En un futuro articulo presentare una defensa muy superior y mas elaborada que detectara ataques incluso sin abrir los puertos. esta defensa bloquea el **99,9911** de los ataque recibidos.

