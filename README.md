## Preparación para la OSCP - Metodología & Scripts

![banner_oscp](https://user-images.githubusercontent.com/87484792/177843931-081eca92-24f1-4743-a632-48ee65b2ba4a.png)

<h2> Enumeración - Fase Inicial </h2>
Enumeración de puertos: </br>

##

`sudo nmap --minrate-5000 -p- -vvv -Pn -n -oG openPorts.txt <ip>` # Encontrar puertos abiertos con nmap </br>

`sudo nmap -sSCV -p{ports} -oN servicesPorts.txt <ip>` # Verificar que servicios hay en los puertos encontrados.

`sudo nmap --script=http-enum  -p {port http/s} <ip>` # Pequeño script de nmap (".nse") para la verificación de directorios en http/s

`sudo nmap -sU -T5 --top-ports 500 <ip> ` # Encontrar puertos abiertos UDP con nmap
