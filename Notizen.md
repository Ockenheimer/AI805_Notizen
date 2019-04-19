# Notizen 2019-04-13

## Informations - und Wissensgesellschaft

	




## Bedrohungslage in der digitalen Gesellschaft

* Bei der Eintwicklung des Inet kein Schwerpunkt auf Sicherheit
* derzeitige Eintwicklung von leitungsbasierten zu paketbasierten Netzen





## Grundlage der Kryptografie

* Vertraulichkeit liefert nicht der Algorithmus, sondern der geheime Schlüssel
* Verschlüsselungsarten
	* ECB
	* CBC 
	* CFM
	* CCM 
* Diffie-Hellmann Verfahren 
	* Problem der diskreten Algorithmen
* RSA-Verfahren
	* Rechnet anders.... vOv 	  
	* Quantencomputer machen RSA kaputt

* Kryptographische Hashfunktion

* Signaturverfahren



## Sicherheitstechnologien

* Netzwerksicherheit
	* Firewall
	* LAN-Security Gateway
	* Intrusion Detection Systeme
	* VPN
		* VPN-Tunneling
	* Authentifizierung
		* verschiedene Authentifizierungsprotokolle
		* Mögliche Klassifizierungen:
			1. Einseitige oder gegenseitige Authentifizierung
			1. Authentifizierung durch dritte
			1. Gegenständliche und persönliche Merkmale
			1. Einmalkennwort-Verfahren
			1. Challenge-Response-Verfahren
			1. RADIUS
			1. KERBEROS
	* WLAN
		*	WPA2 (RSN 802.11i)
			* Vertraulichkeit mit AES-CCM
			* Datenintegrität mit AES-CBC- MAC
			* Zugriffskontrolle von WPA
			 => liefert sehr hohe Sicherheit


## Sicherheitspolitik

Sicherheitspolitik ist Rahmenwert
* Risikoanalyse
* Sicherheitsmanagement
	* organisatorische und rechtliche Maßnahmen


## Prüfungsrelevanz

### IT-Sicherheit: Bedeutung, Sinn und Zweck in digitaler Gesellschaft

#### Bedeutung
IT-Sicherheit ist Beschreibung von Maßnahmen und Vorgehensweise zum Schutz von technischen Systemen. Die IT-Sicherheit analysiert technische Einrichtungen auf sicherheitstechnische Schwachstellen und entwickelt Konzepte zu deren Schutz. 

> - Schutz von Daten, Informationen und Diensten vpr unbefugten Personen
> - Schutz der IT-Systeme gegen Gefahren durch das Internet
> - technische Verfügbarkeit und Stabilität der IT-Systeme
> - Schutz der Daten und Informationen vor Zerstärung, unerlaubtem Abhören und Verändern
> - Festelegung der Zugriffsautorisierung von Personen auf Daten, Dienstleistungen und IT-Systemen
> - Beseitigung von Softwarefehlern in Programmen
> - Vermeidung von Konfigurationsfehlern
> - allgemeine Schutzmaßnahmen
> 	- regelmäßige Schutzmaßnahmen
>		- Zugangskontrolle zu IT-Systemen (PC, Server, Büro oder Gebäude)
>		- Diebstahlschutz
>		- Social Engineering (Sensibilisierung, Schulung, Kontrolle)
> - Schutz vor Sabotage, Wirtschaftsspionage, etc.
> - Schutz vor höherer Gewalt
>
> vgl. Präsentation p.26, S.13 Teil 1

#### Sinn und Zweck in der digitalen Gesellschaft
Bestehende Bedrohungsszenarien der digitalen Gesellschaft durch höheren Grad der Vernetzung, zunehmende Komplexität der eingesetzten Systeme und unzureichender Ausbildung am Gerät
- Beispiele:
	- E-Mails
		- Versand im Klartext
		- fehlende Authentifizierung von Absender und Empfänger
		- Anhänge könen Schadsoftware enthalten
		- Spam (Produktivitäts- und Technologiebremse)
	- Übertragung von Webseiten
		- Googeln als Freizeitvergnügen
		- Passwörter und Kontodaten für Dritte lesbar
		- Side Loading von Schadcode (Mobile Code vgl. <a href="https://en.wikipedia.org/wiki/Code_mobility"> Wiki </a>)
		- falsche Informationen auf Webseite
	- Einsatz fehlerhafter Software (auch BS)
	- Unautorisiertes Eindringen in private Netze
		- DoS-Attacken, Bornetze
		- Phishing, Spyware

IT-Sicherheit kann die Schwachpunkte in der digitalen Gesellschaft aufzeigen und für einen sichereren Umgang mit Daten und Technologien sensibilisieren.

Sie dient der Absicherung des eigenen Rechnernetzes vor anderen Netzen.

IT-Sicherheit bezeichnet den SChutz vor Menschen, die Unberechtigt Informationen und Dienste aus Rechnernetzen zu Ihrem Vorteil, und/oder Nachteil Anderer, verwenden oder IT-Systeme zum Schaden anderer beeinträchtigen wollen.

- IT-Sicherheit = Prozess 
	- umfasst Hardware, Software, Richtlinien und Menschen
- IT-Software != Produkt

### Bedrohung und Angriffsarten (Malware, Spoofing, DoS, Phishing, Man-in-the-Middle, APT)

#### Malware

Überbegriff für **Viren**, **Würmer** und **Trojaner**

##### Virus

- Code der ein Wirtprogramm zur Ausführung benötigt (!= Programm)

- **Infektion**
	- Code wird als Anhang von Programm eingeschleust.
- wird erst aktiv, wenn Wirtprogramm ausgeführt wird
- besitzt Signatur (Muster) wodurch er für Scanner-Programme durch Abgleich erkennbar wird.
- kann in verschiedene Teile unterteilt sein, z.B.:
	- Verschlüsselung
	- Reproduktion
	- Mutation (bei polymorphen Viren)
	- Schadcode
- **Ziel** *Verstecken* vor Anti-Malware-Scannern

##### Würmer
- selsbtändiges Programm mit Routinen zur Replikaton und Weiterverbreitung des Schadcodes
- selbstständige Vervielfältigung und Verbreitung auf alle Rechner eines Netzwerks ohne Interaktion oder Kenntnis des Nutzers 
- bewirkt vor allem Ausfall des Systems (via DoS-Attacke)
- durch **Wurkmkopf** der Kommunkation der Würmer mit anderen infizierten Systemen verwaltet, können ausgelesene Daten bearbeitet werden
- wird meist durch E-Mail-Anhänge verbreitet, zunehmend aber auch automatisch beim Surfen auf manipulierten Seiten (sog. Cross-Site-Scripting (XSS-Atacke))
- sind auf spezielle Betriebssysteme und Script-Sprachen angepasst
- z.Z. häufigste Schadfunktion: öffnet Hintertür (sog. Backdoor) auf infizierten Systemen.

##### Trojaner

- bringt über ein manipuliertes Programm mit (scheinbarer) Nutz-Funktionalität Schadcode auf das System
- Schadcode bewirkt bspw.
	- Zugriff auf befallene Systeme
	- Aufzeichnen von Daten 
	- etc.
- Bestehen meist aus drei Komponenten
	1. Trägerprogramm, welches (scheinbare) Funktionalität anbietet (meist "Mogelpackung")
	2. Installation eines Serverprogramms auf befallenem System
	3. Client auf dem System des Angreifers zur Kommunikation mit dem Server-Programm auf dem befallenen System
- Verbreitung meist über das Internet via Mail oder Download von Webseiten
- Werden oft in den Systemstart integriert
- Angreifer kann Tastatureingaben mitlesen (*Keylogger*) oder Dateien des Rechners auslesen, verändern oder löschen.



#### Spoofing


#### DoS

Denial-of-Service-Attacke

Angreifer versucht das Ziel-System durch eine hohe Anzahl unsinniger Anfragen zu überlasten. Das angegeriffene System kann in Folge dieser Attacek nicht Ihrer normalen Tätigkeit nachgehen.

Um in der Realität eine DoS-Attacke durchzuführen, wird das Zielsystem meist von mehreren Systemen angegriffen. Man spricht hier von einer Distributed-Denial-of-Service (DDoS) -Attacken. Hierfür werden meist Botnetze eingesetzt.



#### Phishing


#### Man-in-the-Middle


#### APT

Advanced-Persistent-Threat



### Kryptographische Verfahren und Methoden (RSA,AES, Modi, DH, Hashfunktionen, Signatur)




### Netzwerksicherheit: Firewall-Systeme, VPN (Funktionsweise)



### Authentifizierungsprotokolle (Passwort, Challenge Response, Kerberos)



### Unternehmensweite IT-Sicherheitspolitik (Vorgehensweise, rechtliche Aspekte, Penetration Testing)
	
	