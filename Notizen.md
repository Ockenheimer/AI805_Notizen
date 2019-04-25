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

Ein Angreifer verwendet die IP-Adresse seines Opfers um in dessen Namen eigene IP-Pakete zu versenden. Hierdurch übernimmt er im Netzwerk die Identität des Opfers.

Warum funktioniert das?
- Die IP-Protokolle vertrauen den eingetragenen (und bekannten) Quelladressen in den Paketen und führen keine erneute Authentifizierung durch.
- Einträge im ARP-Cache sind leicht zu manipulieren, in dem die Verknüpfung von MAC-Adresse und IP-Adresse des Kommunikationspartners zu MAC des Angreifers und IP des Opfers ersetzt wird.


> Der ARP-Cache ist sowas wie ein selbsterstelltes Telefonbuch für das  Netzwerk. Ein neu ins Netz kommender Rechner schickt einen ARP-Request mit seiner MAC- und IP-Adresse. Andere Rechner antworten ihm dann mit Ihrer eigenen Kombination. 

#### DoS

Denial-of-Service-Attacke

Angreifer versucht das Ziel-System durch eine hohe Anzahl unsinniger Anfragen zu überlasten. Das angegeriffene System kann in Folge dieser Attacek nicht Ihrer normalen Tätigkeit nachgehen.

Um in der Realität eine DoS-Attacke durchzuführen, wird das Zielsystem meist von mehreren Systemen angegriffen. Man spricht hier von einer Distributed-Denial-of-Service (DDoS) -Attacken. Hierfür werden meist Botnetze eingesetzt.

##### DoS-Angriffsarten:
> Ich weiß nicht, ob er so genau sein will, aber jetzt steht es mal da

**ARP-Spoofing**
Angreifer ändertden ARP-Cache des Opfers bzw. durch ARP-Reply Pakete mit nicht existierenden MAC-Adressen
vgl. <a href="https://de.wikipedia.org/wiki/Address_Resolution_Protocol">wiki</a>

**MAC Flooding**
Angreifer überflutet einen Switch-Port mit sehr vielen MAC-Frames unbekannter Quelladdressen
vgl. <a href="http://einstein.informatik.uni-oldenburg.de/rechnernetze/mac_frames.htm">MAC-Frames</a> 

Der Switch bekommt vom Angreifer einen MAC-Frame mit unbekannter Quelladresse. Diesen speichert er soweit Speicherplatz vorhanden ist. Ist der Speicher voll, leitet der Switch die Pakete an alle aktiven Ports weiter. Damit werden auch andere Switche im Netzwerk überladen. Schlussendlihc sind alle Speicher in allen Netzwerkgeräten mit sinnlosen MAC-Adressen überlaufen und reguläre Clients können sich nicht per MAC-Frame im Netzwerk anmelden.

**DHCP Starvations**
Angreifer fordert sämtliche verfügbaren IP-Adressen beim DHCP-Server an. Ein regulärer Client kann sich dann nicht mehr mit dem Netzwerk verbinden.
vgl. <a href="https://de.wikipedia.org/wiki/DHCP">wiki</a>

**ICMP Redirects**
Angreifer sendet *ICMP Redirect* Paket über Default Gateway zum Opfer-Host mit nicht existierender Server-IP-Adresse
Opfer übernimmt falsche Adresse und sendet an nicht existenten Server. Da kein Server da ist, bekommt sie auch keine Rückmeldung "falscher Server".
vgl. <a href="https://de.wikipedia.org/wiki/Internet_Control_Message_Protocol">ICMP</a>



#### Phishing

(kurz für Password-Fishing)
Ziel ist das Ausspionierne von Passwörtern und Zugangsdaten zu speziellen Internetplattformen (z.B. Onlinebanking) um sich oder Dritte zu Lasten des opfers zu bereichern.

##### Vorgehensweise
1. Angreifer wählt einen verbreiteten Online-Dienst aus (bekanntes Internetportal z.B. Paypal) und baut die Webseite auf seinem eigenen Webserver täuschend echt nach.
2. Angreifer versendet Mail mit gefälschetem Absender an Opfer (möglichst noch mit persönlichen Informationen des Opfers) und fordert zur Kontaktaufnahme über Link zur eigenen Websiete auf.
3. Auf gefälschter Webseite muss Anwender (echte) Zugangsdaten des Dienstes eingeben.
4. Durch Anzeige einer Fehlermeldung wird ein Problem mit der Webseite angedeutet, der Angreifer unterbricht die Kommunikation mit dem Opfer.
5. Angreifer loggt sich mit den Zugangsdaten des Opfers beim Original-Dienst ein und führt dort weitere Aktionen aus (Überweisungen tätigen, usw.)

##### Arten von Phishing
- Spear-Phishing:
gezielte Mails an Personengruppen oder Einzelpersonen, wobei vorher eingeholte persönliche Informationen über das Opfer in die ail eingebaut werden.
- Trojaner-Phishing
Angreifer ändert durch unbemerkten Zugriff auf des Opfer-System den DNS-Eintrag in den Netzwerkeinstellungen. Hierdurch wird durch Eingabe der korrekten URL der gefälschte Server aufgerufen.
- Man-in-the-Middle-Angriff
mit sog. SSL-Trojaner. Daten werden vor der Verschlüsselung kompromitiert.


#### Man-in-the-Middle

Ein Angreifer schaltet sich in die Kommunikation zwischen A und B und täuscht unbemerkt die Identität des jeweils anderen vor. Er unterhält sich mit B als sei er A und umgekehrt.

Hierdurch bemerken weder A noch B, dass sie eigentlich mit C sprechen. C kann die Schlüsselaushandlung zwischen A und B beobachten und so auch in verschlüsselte Kommunikation eingreifen.

##### ARP-Spoofing
1. Angreifer trennt Verbindung zwischen A und B
2. ARP-Reply Paket mit MAC des Angreifers und IP des Opfers A an B und umgekehrt
3. Nach Erhalt der Antwort speichern Opfer die falsche Zuordnung von MAC und IP (ARP-Poisoning)


#### APT

Advanced-Persistent-Threat
Hochprofessionalisierter Angriff zur Erlangung von bestimmten Informationen oder Zielen.
Angriff ist stets auf das Opfer maßgeschneidert.

Angriff läuft in mehreren Phasen ab, um
1. in das Opfersystem einzudringen
2. Kommunktationskanäle mit dem Angreifer zu installieren 
3. beabsichtigte Tätigkeiten über einen längeren Zeitraum unbemerkt auszuüben

Angriffe sind kaum abzuwehren, da ein sehr detailliertes Fachwissen über die einzelnen Phasen und Arbeitsschritte benötigt wird.

##### Phasen eines APT
1. Preparation (Auskundschaften)
2. Intrusion (Eindringen)
3. Conquering victim network (Kompromittieren, Ausbreitung, Durchdringung, Übernahme des Netzwerks)
4. Hiding presence / Camouflage (Verstecken)
5. Gathering Information / Data Exfiltration (Abgreifen und Ausschleusen von Daten)
6. Maintaining Access (Hintertüt einbauen)
7. Clearing (Spurenbeseitigung)

Phasen werden dynamisch und ggf. mehrfach durchlaufen.

### Kryptographische Verfahren und Methoden (RSA,AES, Modi, DH, Hashfunktionen, Signatur)

krypthologische Verfahren bilden die Grundlage für Sicherheit im Netz
Die Methoden sind zu unterteilen in 

1. Verschlüsselung
2. Integrität
3. Authentizität

Prinzip der Verschlüsselung:
**Vertraulichkeit liefert nicht das Verfahren, dondern der geheime Schlüssel**


#### RSA



#### AES

Blockchiffrenverfahren

##### Typ
symetrische Verschlüsselung mit verschiedenen Blocklängen (16 B, 24 B, 32 B) und Schlüssellänge

##### interne Darstellung
Matrixblock mit 4 Zeilen und Spalten (Abhängig von Blockgröße. grds. 4 Byte pro Spalte)

##### Schlüssellänge
variable Schlüssellänge (128, 192, 256 Bit) geheimer Schlüssel wird rundenweiße Sukzessive Verlängert

> Schlüssel wird über KeyExpansion() auf (Runden+1) * Blockgröße viele Bytes vergrößert. 
> Bsp.: Schlüssel ist "teste" 
> 4 Runden
> Blockgröße sind 6 Zeichen
> Keyexpansion(test) = testet estete stetes tetest eteste 
>
>Beispiel von mir ohne Gewähr



##### Verschlüsselung
Datenamtrix mit Klartextblock als Ausgangswert wird in mehreren Runden durch Substitution und Permutation unter Verknüpfung mit Teilschlüsseln verschlüsselt

##### Rundenanzahl
in Abhängigkeit von Blockgröße und Schlüssellänge 10, 12 oder 14 Runden

##### Operationen je Runde
- SubByte: Substitution jede Byte im Block durch eine Transformation (S-Box)

> Durch nachschauen in der S-Box wird das Byte durch ein anderes Byte ausgetauscht 

- Shift Row: Permutation der Zeilen der Datenmatrix

> Die Blöcke werden zeilenweise (ausgenommen Zeile 1) nach links verschoben. Bei einem 128bit Block wird die Zeile 2 einen Block nach links verschoben, Zeile 3 zwei Blöcke und Zeile 4 drei Blöcke. Diese Art der Permutation geschieht auch bei 160bit und 192bit. Bei 256bit z.B. ist die Permutation Z1 = 0, Z2 = 1, Z3  =3, Z4 = 4.

- MixColumn: Mischen der Bytes in den Spalten der Datenmatrix (Polynom-Multiplikation)

> Matrix-Vektor-Multiplikation mit vorgegebener Matrix (vorgegeben hab ich jett geraten....)

- RoundKey: Bitweise XOR-Verknüpfung mit Rundenschlüssel (als Teil des erweiterten Schlüssels)


vgl. zu AES komplett <a href="http://www.weblearn.hs-bremen.de/risse/RST/WS05/AES_CryptoLoop.pdf"> HS-Bremen</a>

#### Modi

##### ECB
Electronic Code Book

jeder Block wird für sich verschlüsselt. Es besteht keine Abhängigkeit zu den anderen Blöcken.

Bedeutet aber auch, dass zwei gleiche Blöcke gleich verchlüsselt werden.

Die Nachricht kann jedoch auch dann noch entschlüsselt werden, wenn einzelne Teile fehlen.


##### CBC
Cipher Block Chaining

jeder Klartextblock wird mit dem vorhergehenden chifrierten Block XOR-verknüpft

Somit ergibt sich eine Abhängigkeit zwischen den Blöcken.
Der letzte lock ist gleichsam die Prüfsumme für die gesamte Datei. (ist vorher ein Block verändert worden, stimmt die Prüfsumme nicht mehr)

Dies bedeutet, dass ist ein Block beschädigt oder verloren gegangen, können die nachfolgendenen Blöcke nicht mehr entschlüsselt werden.


#### DH
Diffie-Hellmann-Verfahren

##### Typ
Sitzungsschlüssel-Vereinbarungsdienst

##### Initialisierung 



#### Hashfunktion



#### Signatur




### Netzwerksicherheit: Firewall-Systeme, VPN (Funktionsweise)



### Authentifizierungsprotokolle (Passwort, Challenge Response, Kerberos)



### Unternehmensweite IT-Sicherheitspolitik (Vorgehensweise, rechtliche Aspekte, Penetration Testing)
	
	