# Zusammenfassung

## IT-Sicherheit: Bedeutung, Sinn und Zweck in digitaler Gesellschaft

### Bedeutung
IT-Sicherheit ist Beschreibung von Maßnahmen und Vorgehensweise zum Schutz von technischen Systemen. Die IT-Sicherheit analysiert technische Einrichtungen auf sicherheitstechnische Schwachstellen und entwickelt Konzepte zu deren Schutz. 

> - Schutz von Daten, Informationen und Diensten vpr unbefugten Personen
> - Schutz der IT-Systeme gegen Gefahren durch das Internet
> - technische Verfügbarkeit und Stabilität der IT-Systeme
> - Schutz der Daten und Informationen vor Zerstärung, unerlaubtem Abhören und Verändern
> - Festelegung der Zugriffsautorisierung von Personen auf Daten, Dienstleistungen und IT-Systemen
> - Beseitigung von Softwarefehlern in Programmen
> - Vermeidung von Konfigurationsfehlern
> - allgemeine Schutzmaßnahmen
>		- regelmäßige Schutzmaßnahmen
>		- Zugangskontrolle zu IT-Systemen (PC, Server, Büro oder Gebäude)
>		- Diebstahlschutz
>		- Social Engineering (Sensibilisierung, Schulung, Kontrolle)
> - Schutz vor Sabotage, Wirtschaftsspionage, etc.
> - Schutz vor höherer Gewalt
>
> vgl. Präsentation p.26, S.13 Teil 1

### Sinn und Zweck in der digitalen Gesellschaft
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

## Bedrohung und Angriffsarten (Malware, Spoofing, DoS, Phishing, Man-in-the-Middle, APT)

### Malware

Überbegriff für **Viren**, **Würmer** und **Trojaner**

#### Virus

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

#### Würmer
- selsbtändiges Programm mit Routinen zur Replikaton und Weiterverbreitung des Schadcodes
- selbstständige Vervielfältigung und Verbreitung auf alle Rechner eines Netzwerks ohne Interaktion oder Kenntnis des Nutzers 
- bewirkt vor allem Ausfall des Systems (via DoS-Attacke)
- durch **Wurkmkopf** der Kommunkation der Würmer mit anderen infizierten Systemen verwaltet, können ausgelesene Daten bearbeitet werden
- wird meist durch E-Mail-Anhänge verbreitet, zunehmend aber auch automatisch beim Surfen auf manipulierten Seiten (sog. Cross-Site-Scripting (XSS-Atacke))
- sind auf spezielle Betriebssysteme und Script-Sprachen angepasst
- z.Z. häufigste Schadfunktion: öffnet Hintertür (sog. Backdoor) auf infizierten Systemen.

#### Trojaner

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



### Spoofing

Ein Angreifer verwendet die IP-Adresse seines Opfers um in dessen Namen eigene IP-Pakete zu versenden. Hierdurch übernimmt er im Netzwerk die Identität des Opfers.

Warum funktioniert das?
- Die IP-Protokolle vertrauen den eingetragenen (und bekannten) Quelladressen in den Paketen und führen keine erneute Authentifizierung durch.
- Einträge im ARP-Cache sind leicht zu manipulieren, in dem die Verknüpfung von MAC-Adresse und IP-Adresse des Kommunikationspartners zu MAC des Angreifers und IP des Opfers ersetzt wird.


> Der ARP-Cache ist sowas wie ein selbsterstelltes Telefonbuch für das  Netzwerk. Ein neu ins Netz kommender Rechner schickt einen ARP-Request mit seiner MAC- und IP-Adresse. Andere Rechner antworten ihm dann mit Ihrer eigenen Kombination. 

### DoS

Denial-of-Service-Attacke

Angreifer versucht das Ziel-System durch eine hohe Anzahl unsinniger Anfragen zu überlasten. Das angegeriffene System kann in Folge dieser Attacek nicht Ihrer normalen Tätigkeit nachgehen.

Um in der Realität eine DoS-Attacke durchzuführen, wird das Zielsystem meist von mehreren Systemen angegriffen. Man spricht hier von einer Distributed-Denial-of-Service (DDoS) -Attacken. Hierfür werden meist Botnetze eingesetzt.

#### DoS-Angriffsarten:
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



### Phishing

(kurz für Password-Fishing)
Ziel ist das Ausspionierne von Passwörtern und Zugangsdaten zu speziellen Internetplattformen (z.B. Onlinebanking) um sich oder Dritte zu Lasten des opfers zu bereichern.

#### Vorgehensweise
1. Angreifer wählt einen verbreiteten Online-Dienst aus (bekanntes Internetportal z.B. Paypal) und baut die Webseite auf seinem eigenen Webserver täuschend echt nach.
2. Angreifer versendet Mail mit gefälschetem Absender an Opfer (möglichst noch mit persönlichen Informationen des Opfers) und fordert zur Kontaktaufnahme über Link zur eigenen Websiete auf.
3. Auf gefälschter Webseite muss Anwender (echte) Zugangsdaten des Dienstes eingeben.
4. Durch Anzeige einer Fehlermeldung wird ein Problem mit der Webseite angedeutet, der Angreifer unterbricht die Kommunikation mit dem Opfer.
5. Angreifer loggt sich mit den Zugangsdaten des Opfers beim Original-Dienst ein und führt dort weitere Aktionen aus (Überweisungen tätigen, usw.)

#### Arten von Phishing
- Spear-Phishing:
gezielte Mails an Personengruppen oder Einzelpersonen, wobei vorher eingeholte persönliche Informationen über das Opfer in die ail eingebaut werden.
- Trojaner-Phishing
Angreifer ändert durch unbemerkten Zugriff auf des Opfer-System den DNS-Eintrag in den Netzwerkeinstellungen. Hierdurch wird durch Eingabe der korrekten URL der gefälschte Server aufgerufen.
- Man-in-the-Middle-Angriff
mit sog. SSL-Trojaner. Daten werden vor der Verschlüsselung kompromitiert.


### Man-in-the-Middle

Ein Angreifer schaltet sich in die Kommunikation zwischen A und B und täuscht unbemerkt die Identität des jeweils anderen vor. Er unterhält sich mit B als sei er A und umgekehrt.

Hierdurch bemerken weder A noch B, dass sie eigentlich mit C sprechen. C kann die Schlüsselaushandlung zwischen A und B beobachten und so auch in verschlüsselte Kommunikation eingreifen.

#### ARP-Spoofing
1. Angreifer trennt Verbindung zwischen A und B
2. ARP-Reply Paket mit MAC des Angreifers und IP des Opfers A an B und umgekehrt
3. Nach Erhalt der Antwort speichern Opfer die falsche Zuordnung von MAC und IP (ARP-Poisoning)


### APT

Advanced-Persistent-Threat
Hochprofessionalisierter Angriff zur Erlangung von bestimmten Informationen oder Zielen.
Angriff ist stets auf das Opfer maßgeschneidert.

Angriff läuft in mehreren Phasen ab, um
1. in das Opfersystem einzudringen
2. Kommunktationskanäle mit dem Angreifer zu installieren 
3. beabsichtigte Tätigkeiten über einen längeren Zeitraum unbemerkt auszuüben

Angriffe sind kaum abzuwehren, da ein sehr detailliertes Fachwissen über die einzelnen Phasen und Arbeitsschritte benötigt wird.

#### Phasen eines APT
1. Preparation (Auskundschaften)
2. Intrusion (Eindringen)
3. Conquering victim network (Kompromittieren, Ausbreitung, Durchdringung, Übernahme des Netzwerks)
4. Hiding presence / Camouflage (Verstecken)
5. Gathering Information / Data Exfiltration (Abgreifen und Ausschleusen von Daten)
6. Maintaining Access (Hintertüt einbauen)
7. Clearing (Spurenbeseitigung)

Phasen werden dynamisch und ggf. mehrfach durchlaufen.

## Kryptographische Verfahren und Methoden (RSA,AES, Modi, DH, Hashfunktionen, Signatur)

krypthologische Verfahren bilden die Grundlage für Sicherheit im Netz
Die Methoden sind zu unterteilen in 

1. Verschlüsselung
2. Integrität
3. Authentizität

Prinzip der Verschlüsselung:
**Vertraulichkeit liefert nicht das Verfahren, dondern der geheime Schlüssel**


### RSA

ist ein asymetrisches Schlüsselverfahren, welches mit Public und Privat-Key arbeitet

#### Schlüsselbeschaffung
1. es werden zwei große Primzahlen gebildet (z.B. p=11 und q=19) und deren Produkt n gebildet ( n = p * q). Daraus ermittelt man phi(n) = p-1 * q-1 also in diesem Beispiel 180
2. es wird ein Verschlüsselungswert e gewählt welcher die Voraussetzung hat ggt(e,180)=1
3. es wird ein Entschlüsselungswert d gesucht welcher die Eigenschaft hat (d * e) mod(phi(n))=1
4. Öffentlich bekannt sind e und n

#### Verschlüsseln
Eine Nachricht m wird verschlüsselt mit der Formel m^e mod n

#### Entschlüsseln
Eine verschlüsselte Nachricht c wird entschlüsselt mittels c^d mod n


#### Beispiel
p=11
q=19

n= 11 * 19 = 209

phi(n) = 10 * 18 = 180

e = z.B. 511 (ggt(511,180)=1)

d = 31 (WolframAlpha sei Dank)
> (31 * 511)mod180 = 1
> Eingabe (d * 511)mod180 wird von wolframAlpha nach d aufgelöst

geheime Nachricht m = 200

#####Verschlüsseln

200^511mod209 ergibt 167

#####Entschlüsseln

167^31mod209 ergibt 200




### AES

Blockchiffrenverfahren

#### Typ
symetrische Verschlüsselung mit verschiedenen Blocklängen (16 B, 24 B, 32 B) und Schlüssellänge

#### interne Darstellung
Matrixblock mit 4 Zeilen und Spalten (Abhängig von Blockgröße. grds. 4 Byte pro Spalte)

#### Schlüssellänge
variable Schlüssellänge (128, 192, 256 Bit) geheimer Schlüssel wird rundenweiße Sukzessive Verlängert

> Schlüssel wird über KeyExpansion() auf (Runden+1) * Blockgröße viele Bytes vergrößert. 
> Bsp.: Schlüssel ist "teste" 
> 4 Runden
> Blockgröße sind 6 Zeichen
> Keyexpansion(test) = testet estete stetes tetest eteste 
>
>Beispiel von mir ohne Gewähr



#### Verschlüsselung
Datenamtrix mit Klartextblock als Ausgangswert wird in mehreren Runden durch Substitution und Permutation unter Verknüpfung mit Teilschlüsseln verschlüsselt

#### Rundenanzahl
in Abhängigkeit von Blockgröße und Schlüssellänge 10, 12 oder 14 Runden

#### Operationen je Runde
- SubByte: Substitution jede Byte im Block durch eine Transformation (S-Box)

> Durch nachschauen in der S-Box wird das Byte durch ein anderes Byte ausgetauscht 

- Shift Row: Permutation der Zeilen der Datenmatrix

> Die Blöcke werden zeilenweise (ausgenommen Zeile 1) nach links verschoben. Bei einem 128bit Block wird die Zeile 2 einen Block nach links verschoben, Zeile 3 zwei Blöcke und Zeile 4 drei Blöcke. Diese Art der Permutation geschieht auch bei 160bit und 192bit. Bei 256bit z.B. ist die Permutation Z1 = 0, Z2 = 1, Z3  =3, Z4 = 4.

- MixColumn: Mischen der Bytes in den Spalten der Datenmatrix (Polynom-Multiplikation)

> Matrix-Vektor-Multiplikation mit vorgegebener Matrix (vorgegeben hab ich jett geraten....)

- RoundKey: Bitweise XOR-Verknüpfung mit Rundenschlüssel (als Teil des erweiterten Schlüssels)


vgl. zu AES komplett <a href="http://www.weblearn.hs-bremen.de/risse/RST/WS05/AES_CryptoLoop.pdf"> HS-Bremen</a>

### Modi

#### ECB
Electronic Code Book

jeder Block wird für sich verschlüsselt. Es besteht keine Abhängigkeit zu den anderen Blöcken.

Bedeutet aber auch, dass zwei gleiche Blöcke gleich verchlüsselt werden.

Die Nachricht kann jedoch auch dann noch entschlüsselt werden, wenn einzelne Teile fehlen.


#### CBC
Cipher Block Chaining

jeder Klartextblock wird mit dem vorhergehenden chifrierten Block XOR-verknüpft

Somit ergibt sich eine Abhängigkeit zwischen den Blöcken.
Der letzte lock ist gleichsam die Prüfsumme für die gesamte Datei. (ist vorher ein Block verändert worden, stimmt die Prüfsumme nicht mehr)

Dies bedeutet, dass ist ein Block beschädigt oder verloren gegangen, können die nachfolgendenen Blöcke nicht mehr entschlüsselt werden.

#### CTR
Counter Mode

Der Klartext wird nicht mit der Verschlüsselungsfunktion E verschlüsselt

Stattdessen wird ein Zähler z verschlüsselt.

##### Ablauf
1. Initialisierung eines Zählers z z.B. mit 1 (üblicherweise eine große Zahl)
2. E wird auf z angewendet
3. mit E(z) wird der Klartext-Block m^1 mod(2) addiert (XOR)
4. z++
5. GOTO 2 

##### Vorteil
Eine Entschlüsselung ist als Funktion D nciht notwendig
Der Empfänger kann den verschlüsselten Text c einfach Blockweise erneut "verschlüsseln" und erhält dadurch den Klartext m zurück. ER benötigt nur den Startwert z den man im Klartext übermittelt




### DH
Diffie-Hellmann-Verfahren

#### Typ
Sitzungsschlüssel-Vereinbarungsdienst

#### Vorgehen 
1. Es wird über einen öffentlichen Kanal eine hohe Primzahl p und eine gemeinsame Zahl g kleiner als p ausgehandelt.
2. Jeder Teilnehmer wählt eine zufällige Zahl r
3. Die Teilnehmer berechnen jeweils (g^r mod p) und tauschen Ihre Ergebnisse E aus
4. mit dem Ergebnis des jeweils anderen rechnen Sie (E^r mod p) und bekommen einen gemeinsamen und gleichen Schlüssel k

#### Rechenbeispiel
Ausgehandelt werden p = 59 und g = 29

A nimmt Zufallszahl r = 2<br>
B nimmt Zufallszahl r = 3

A rechnet 29^2 mod 59 und erhält **15** <br>
B rechnet 29^3 mod 59 und erhält **22**

A rechnet dann 22^2 mod 59 und erhält **12**<br>
B rechnet dann 15^3 mod 59 und erhält **12**

der geheime Schlüssel ist ***12***


### Hashfunktion

> Hash-Funktionen sind eine Art "Fingerabdruck" für große Dateien. Wird das Dokument verändert, passt es nicht mehr zum Fingerabdruck (vgl. Lang 2018, S. 191)

Diese Art der Funktion wird zur Verifikation eines Dokumentes verwendent.

Eine zweite Nutzung ist die Speicherung von Passwörtern. Wird eine gehashte Datenbank entwendet, lässt sich kein Rückschluss auf das Passwort ziehen. 

Zum Dritten nutzt man Hashes für den schnellen Zugriff auf große Datenpakete.

#### Kollisionen

In jedem Hash-Verfahren gibt es nur eine endliche Anzahl von Kombinationen für Daten. Dies bedeutet, dass es unendlich viele Daten gibt, die den gleichen Hash-Wert zurückgeben.

Hieraus folgt, dass eine Hash-Funktion nicht injektiv ist. Von einem Hash kann in der Regel nicht auf einen bestimmten Ursprungswert zurück gerechnet werden.(Im Gegensatz zur Verschlüsselung)

Ergeben zwei unterschiedliche Daten den gleichen Hash spricht man von Kollisionen. Ist es in endlicher Zeit möglich, Daten zu finden, die den selben Hash-Wert ergeben, kann das Hash-Verfahren als unsicher bezeichnet werden.

#### Prinzip

Aus einer Nachricht von beliebiger Länge wird ein Hashwert mit fester Länge gebildet.

- One-Way-Funktion:<br>
Soll heißen der Rückschluß vom Hash auf die ursprüngliche Nachricht ist nahezu unmöglich.

- collision-resistant:<br>
Es ist fast unmöglich, dass zwei Nachrichten den selben Hash-Wert ergeben.

- second Preimage-resistant:<br>
Selbst wenn ein Angreifer eine Passwort-Hashkombination weiß, kann er hierdurch keine Kollisionenen bei anderen Hashes errechnen.

Der Nachrichtenaustausch wird üblicherweise durch eine Verschlüsselung der Nachricht unterstützt, sodass ein Angreifer nicht Nachricht und Hash zugleich austauschen kann. Durhc die zusätzliche Verschlüsselung der Nachricht erreicht man <b>Datenintegrität</b>

#### Klassifikation von Hash-Funktionen

- Modification Detection Code<br>
Nachricht belieber Länge wird durch spezielle Kompressionsverfahren auf wenige Bytes komprimiert.

> vgl. **SHA-1** (160 Bits) o. **SHA-2** (256 Bits)

- Message Authentication Code<br>
Parametrisierung durch symmetrisches Verschlüsselungsverfahren mit geheimen Schlüssel (keyed Hashfunction)

> vgl. MAC-AES

**Kombination der Verfahren**
>> HMAC
>> zweimalige Anwendung des Kompressionsverfahrens auf die mit einem geheimen Schlüssel verkettete Nachricht.


#### SHA-1

SHA-1 ist ein mittlerweile veraltetes Hash-Verfarhen, welches schlussendlich einen 160-bit langen Hash ausgibt.

Im weiteren folgt der Ablauf des Verfahrens

##### Vorbereitung Dokument auffüllen.

Das Dokument m wird soweit aufgefüllt, dass die Länge des Dokumentes ein mehrfaches von 512 ergibt.
Anschließend prüft der Algorithmus mittels mod(512) ob noch mindestens 64 bit in der Nachricht frei sind.
Ist dies nicht der Fall, wird ein zusätzlicher 512 Bit-Block angehängt.

In die letzten 64 bit von m wird die Länge des Dokumentes abgelegt. Der Zwischenraum von Nachricht bis Länge wird mit *100000...* aufgefüllt.

##### Vorbereitung Dokument expandieren

Das Dokument m wird nun in 512-Bit-Blöcke unterteilt. Jeder Block wird dann in 80 Wörter je 32 Bit expandiert.

Hierzu werden zunächst 16 Wörter á 32 Bit aufgeteilt (W0, W1, W2, usw)
Die fehlenden 64 Wörter W(j) werden dann wie folgt berechnet:<br>
>W(j)=(W(j-3)+W(j-8)+W(j-14)+W(j-16))
Die Addition wird mod2 durchgeführt

##### Hashen

Ich denk mal, es wird nicht erwartet, die Hash-Funktion von SHA-1 darzustellen. Wäre auch albern.
Soviel sei nur gesagt:
- Jeweils 20 Wörter werden über 20 Runden "ge-XOR-ed" und danach addiert

Zum Schluss bleibt aus jedem 512-Bit-Block ein 160-Bit Hash über

Der letztendliche Hash des gesamten Dokumentes m ergibt sich dann aus der mod(2)-Addition aller Hashes der einzelnen Blöcke.




### Signatur

#### Anforderung an Unterschriften
Prinzipiell soll eine Unterschrift folgende Eigenschaften haben
- Authentizität
- Integrität
- Verbindlichkeit

##### Authentizität
Empfänger B soll sich sicher sein, dass Absender A diese Nachricht "unterschrieben" also verifiziert haben.

##### Integrität
Die Signatur soll mit dem unterschriebenen Dokument untrennbar verbunden sein.

##### Verbindlichkeit
Es soll jederzeit nachprüfbar sein, dass A die Unterschrift geleistet hat. A selber soll nicht bestreiten können, diese Unterschrift geleistet zu haben.

#### technische Lösung

Wie setzt man diese Anforderungen in der Realität um?

Denkbar wäre, die gesamte Nachricht m durch A's geheimen Schlüssel verschlüsseln zu lassen. B könnte dann die versclüsselte Nachricht c mit A's öffentlichem Schlüssel entschlüsseln und wäre sicher, dass A diese verifiziert hat.

Da m aber auch einige MB groß sein kann und c dadurch unnötig groß werden würde, wird stattdessen wie folgt vorgegangen.

1. Nachricht m wird gehasht

2. Der Hash wird mit A's geheimen Schlüssel verschlüsselt und an den unverschlüsselten Text m als Signatur s angehangen

3. Der so "signierte" Text wird versendet

4. B wiederrum hasht die bei ihm eingegangene Nachricht m und entschlüsselt s zurück zum Hash vom ursprünglichen m

5. Stimmen der von B erstellte Hash mit dem aus s entschlüsselten überein, wurde m auf dem Weg von A nach B nicht verändert.




## Netzwerksicherheit: Firewall-Systeme, VPN (Funktionsweise)

### Firewall-Systeme

#### Bestandteile

**Technik**
Anordnung zwischen zwei Netzen mit unterschiedlich hohem SChutzbedarf (auch innerhalb des Unternehmens)

**Sicherheitspolitik**
Zugriff auf Komponenten und Ressourcen des zu schützenden Netzes und/oder Kommunikation zwischen den Netzen nur in Übereinstimmung mit Sicherheitskonzept (e.g. Zugangskontollen bereitstellen)

**Grundsatz:** Alles was nicht erlaubt ist, ist verboten!

Es müssen Entscheidungen getroffen werden:
- Welche Rechner dürfen mit welchen Diensten nach außen gehen/von außen erreichbar sein (HTTP, FTP, SMTP, usw.)?
- Welche Benutzergruppen gibt es?
- Wie wird auf erkannte Angriffe reagiert?


**Sicherheitsmanagement**

- Protokollierung von Zugriffen
- Intrusion Detection Risikomanagement
- Notfallmanagemen
- Audits nach IT-Sicherheitspolitik
- Schulung von MA
- Schutz der Firewall-Komponenten
- etc.


#### Firewallarten

##### Paketfilter *Screening Router*

- Router mit IP- und Portfilter auf Netzwerk- und Transportschicht
- Informationen für die Filter werden aus dem IP- bzw. TCP/UDP-Header ausgelesen und zur Filterung verwendet.
- für ein- und ausgehende Pakete können unterschiedliche Regeln eingerichtet werden.
- Regeln werden nacheinander abgearbeitet
	- greift eine der Regeln, wird das Paket verworfen. Eine weitergehende Prüfung findet nicht statt

mögliche Reaktionen:
- Pakete werden geroutet
- Pakete werden abgeblockt
- Pakete werden verworfen

Blockierte oder verworfene Pakete werden protokolliert.

**Sonderfall: Dynamische Paketfilter**

Funktioniert wie statischer Paketfilter, kann jedoch temporär dynamische Zugangsregeln einrichten.

>Bsp.:
>Von einem ausgehenden UDP-Paket werden sowohl Quell- als auch Zieladresse und -Port temporär gespeichert. Erfolgt in einer gewissen Zeitspanne eine entsprechende Antwort mit den gleichen Adressen, wird das Paket ins gesicherte Netz weitergelassen. Kommt das Paket ausserhalb der erwarteten Antwortzeit, wird dieses abgeblockt oder verworfen.

Funktionsweise kann auch umgedreht werden. 
>Zugriffe auf bestimmte Rechner mit mehr als n Zugriffen/Minute werden für m Minuten gesperrt.


##### Verbindungs-Gateway *Circuit-Level-Gateway, Bastion Router, Proxy-Server*
Trennung zweier Netze durch einen Rechner mit je einem Anschluß für das lokale Netz sowie das externe Netz (*Dual Homed Gateway*)
Filterfunktionalität auf der Transportschicht

##### Application-Gateway *Application-Level-Gateway, kurz Proxy*
Stellt eine komplexe Filterfunktionalität auf der Anwendungsschicht bereit (z.B. Telnet, SSH, usw.)
Dienstspezifische Kontrollen möglich 

Anwendungsprogramm welches sich dem Server gegenüber als Client ausgibt, dem Client gegenüber als Server.

Filterung der Daten erfolgt auf der Anwendungsebene. Das heißt, der Proxy hat Kenntnis von der jeweiligen Anwendung und den Anforderungen dieser Anwendung.

Durch einen differenzierten Austhentifikationsmechanismus können zu einzelnen Anwedngunen Zugangskontrollen dargestellt werden.


#### Firewall-Architekturen
Die Firewall-Arten werden zu Systemen zusammengeschlossen, um die unterschiedlichen Aufgaben bestmöglich zu erfüllen.

Diese Systeme müssen aus Sicht des zu schützendenen Systems "so weit außen wie möglich" platziert werden.

Zwischen dem internen und externen Netz wird ein zsätzliches Subnetz abgetrennt, welches von innen und außen nur durch Paketfilter erreicht werden kann. Es wird als screened subnet (oder auch DMZ) bezeichnet.

#### Fazit zentrale Firewall

- kontrollieren und analysieren die Kommunikation auf Netzwerk-, Transport- und Anwendungsebene (ein- wie ausgehend)
- prüfen, welche Rechnersysteme miteinander kommunizieren dürfen
- prüfen, welche Benutzer eine Kommunikation aufbauen dürfen
- überprüfen die Echtheit der Benutzer (Authentifikation)
- protokollieren Aktivitäten und Ereignisse
- reagieren auf vordefinierte Ereignisse
- schützen nicht vor internen Angriffen
- schützen nicht vor Angriffen, die über andere Netzzugänge laufen



### VPN (Funktionsweise)

- Sicherer Datentransfer zwischen zwei oder mehr lokalen Netzen über offene unsichere Netze durch Emulation eines homogenen virtuellen Netzes
- Gewährleistung von Vertraulichkeit der Information, Integrität der Daten und / oder Authentifikation der Kommunikationspartner durch Tunneling
- Ggf. Bereitstellung von Audit- und Accounting-Informationen

#### Funktionsweise
Ein VPN kann auf verschiedenen OSI-Ebenen eingerichtet werden, Daher ist die Funktionsweise sehr allgemein erklärt

**Encapsulatinion**
Die Pakete des zu tunnelnden Protokolls (z.B. IP-Pakete) bekommt einen zusätzlichen Header (den sog. Tunnel-Header) am Startpunkt des Tunnels (VPN-Gateway, bzw. VPN-Client)

**Routing**
Im Tunnelheader befinden sich die Informationen zum Routing, der Verschlüsselung, usw. 
Aufgrund dieser Informationen wird das Paket über das WAN bis zum Tunnelendpunkt geroutet.

**Decapsulation**
Am Tunnelendpunkt (VPN-Server, bzw. weiteres VPN-Gateway) wird der zusätzliche Tunnelheader entfernt. Ggf. wird eine Entschlüsselung des hinterlegten Pakets durchgeführt.


#### Vorteile von Tunneling

**Extranet Access**

- Sichere Vernetzung mit Kunden, Lieferanten und Partnern

**Intranet Access**

- Standortvernetzung großer Unternehmen zu einem virtuellen Netz
- Remote-Access von Außendienstmitarbeitern über das Internet zum Unternehmensnetz

**Sichere Punkt-zu-Punkt-Verbindung durch Tunneling**

- Nutzerdaten und IP-Header der Pakete bleiben im Tunnel verborgen. Sichtbar ist nur der VPN-Header. Eine Verkehrsflußanalyse des internen Netzes ist nicht möglich
- Nur Quell- und Zieladresse des Tunnels sind sichtbar
- Kapselung und Entkapselung erfolgen in den Endpunkten


## Authentifizierungsprotokolle (Passwort, Challenge Response, Kerberos)

Authentifizierungsprotokolle sind wichtig, um den Zugang zu bestimmten Diensten, Anwendungen oder Daten nur für berechtigte Personen bereitszustellen. Eine Verwendung durch Unbefugte soll in jedem Fall verhindert werden.

### Passwort
Einseitige Authentifizierung durch Kenntnis eines bestimmten alphanummerischen Merkmals 

#### Ablauf

1. Server (S) fordert Client (C) zur Identifizierung auf
2. C identifiziert sich mit seiner Kennung (Login/ z.B. NT-User)
3. S fordert C zur Authentifizierung auf
4. C authentifiziert seine Identität mit dem zum Login gehörenden Passwort
5. S antwortet mit Success oder Failure

#### Risiken

- Passwort wird im Klartext übertragen und ist somit mitlesbar
- Passwort ist zu kurz oder zu einfach und wird erraten



### Challenge Response



### Kerberos



## Unternehmensweite IT-Sicherheitspolitik (Vorgehensweise, rechtliche Aspekte, Penetration Testing)
	

###Vorgehensweise




### rechtliche Aspekte



### Penetration Testing
