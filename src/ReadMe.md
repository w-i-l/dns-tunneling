<h2>O sumarizare</h2>
<a href="https://www.youtube.com/watch?v=UVR9lhUGAyU">DNS from Fireship</a> - 100 seconds
<br>
<a href="https://www.youtube.com/watch?v=27r4Bzuj5NQ">ByteByteGo's video</a>

<h2>Resurse</h2>
<a href="https://datatracker.ietf.org/doc/html/rfc1035">Standardul DNS</a> - o lucrare detaliata
<br>
<a href="https://www.cloudflare.com/en-gb/learning/dns/what-is-dns/">Cloudflare explanation</a>
<br>
<a href="https://www.youtube.com/watch?v=HdrPWGZ3NRo&list=PLBOh8f9FoHHhvO5e5HF_6mYvtZegobYX2">DNS tutorial in Python</a>

<h2>Cum sa folosesti</h2>
<p>Nu e nevoie de nicio librarie suplimentare, toate librariile folosite fiind preinstalate din Python.</p>
<p>Se ruleaza <code>python3 dns.py</code> ce porneste serverul de dns local.</p>
<p>Pentru a face un query se poate folosi <a href="https://www.ibm.com/docs/en/aix/7.1?topic=d-dig-command">dig</a> pentru sistemele Unix:</p>
<code>dig example.com @127.0.0.1</code>
<p>sau <a href="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup">nslookup</a> pentru sistemele Windows:</p>
<code>nslookup example.com 127.0.0.1</code>

<br>
<p>Domeniile suportate ca si mocked data sunt <code>example.com</code> si <code>test.com</code>, amandoua avand suport pentru <code>A</code>, <code>SOA</code>, <code>MX</code>, <code>TXT</code>, <code>CNAME</code>.</p>

<h3>Exemplu de output</h3>

```bash
    ; <<>> DiG 9.10.6 <<>> example.com @127.0.0.1 txt
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25472
    ;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;example.com.                   IN      TXT

    ;; ANSWER SECTION:
    example.com.            3600    IN      TXT     "v=spf1 ip4:123.123.123.123 -all"

    ;; AUTHORITY SECTION:
    example.com.            3600    IN      SOA     ns1.example.com. admin.example.com. 2024051501 3600 1800 1209600 3600

    ;; Query time: 0 msec
    ;; SERVER: 127.0.0.1#53(127.0.0.1)
    ;; WHEN: Mon May 27 12:52:48 EEST 2024
    ;; MSG SIZE  rcvd: 141
```

<h2>Detalii implementare</h2>
<p>Protocolul DNS se bazeaza pe UPD si portul 53. De asemenea acesta are un header specific care determina mai multe prorpietato:</p>

```
                               1  1  1  1  1  1
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

<p>Flagurile reprezinta si pot avea urmatoarele valori:</p>
<ul>
    <li>QR - Query/Response</li>
    <li>Opcode - Tipul de query</li>
    <li>AA - Authoritative Answer - specifica daca serverul detine autoritate asupra informatiei oferite</li>
    <li>TC - Truncated</li>
    <li>RD - Recursion Desired - daca dorim sa parcurgem mai multe servere pentru a primi un raspuns</li>
    <li>RA - Recursion Available - daca serverul poate parcurge si alte servere</li>
    <li>Z - Zero - reserved for future use</li>
    <li>RCODE - Response Code - daca a aparut vreo eroare se va specifica aici codul erorii</li>
</ul>
<p>In fisierul <code>dns_enums.py</code> se gasesc mai multe explicatii pentru fiecare flag, dar si toate tipurile suportate de server.</p>

<p>Pentru raspunsul oferit de server, va trebui sa encodam informatia in functie de tipul de query ales.(A, MX, TXT, ...)</p>

<h2>Cum functioneaza</h2>

<p>Vom explica ce se intampla de fapt in functia main din codul serverului, facand abstractie de implementarea parserului de DNS:</p>

```python
LOOPBACK_IP = '127.0.0.1'
GOOGLE_DNS_IP = '8.8.8.8'
DNS_PORT = 53
```

<p>Setam ip pe care vom lucra - localhost, ip-ul serverului Googgle, si portul DNS - 53.</p>

```python
def redirect_to_google(query: bytes) -> tuple[bytes, DNSHeaderResponseCode]:
    '''
    Redirects the query to google and returns the response data and response code
    '''

    google_connection = socket.socket(
        socket.AF_INET, # IPv4 
        socket.SOCK_DGRAM # UDP
    )

    # send the original query to google
    google_connection.sendto(query, (GOOGLE_DNS_IP, DNS_PORT))
    
    google_data, _ = google_connection.recvfrom(1024)
    google_connection.close()

    # get the response code from the google response
    dns_header = DNSHeader(google_data)
    response_code = dns_header.flags.rcode

    return google_data, response_code
```

<p>Functia <code>redirect_to_gogle</code> accepta ca si argument bytes trimisi catre serverul nostru si se ocupa cu redirectionarea requestului catre serverul Goggle, returnand raspunsul oferit de server.</p>

```python
    DNSAnswear.load_zones()
```
<p>Incarcarea in memorie a tuturor fisierelor <code>.zone</code> ce represinta domeniile pe care le avem in subordine.</p>

<p>Functia main este mai mare asa ca o sa o impartim in mai multe parti:</p>

```python
    connection = socket.socket(
        socket.AF_INET, # IPv4 
        socket.SOCK_DGRAM # UDP
    )

    connection.bind((LOOPBACK_IP, DNS_PORT))
```
<p>Deschiderea unei conexiuni pe care ascultam cererile si le procesam secvential.</p>

```python
    print("--------------------")
    data, address = connection.recvfrom(1024) # buffer size

    curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
    packet = DNSPacket(data)
    print(f"[{curent_date}] Received request for \"{packet.question.domain}\"")
```

<p>Primirea datelor de la client si afisarea formatata pentru log-ul serverului</p>


```python
    if response_code == DNSHeaderResponseCode.NAME_ERROR and packet.header.flags.rd == DNSHeaderRecursionDesired.RECURSION:
        print(f"[{curent_date}] Redirecting to Google")

        response_data, response_code = redirect_to_google(data)
        # send the response back to the client
        connection.sendto(response_data, address)

        print(f"[{curent_date}] Responded from Google with {response_code.name} for \"{packet.question.domain}\"")
        continue
```
<p>Daca nu putem rezolva domeniul query-ului si se doreste recursie, trimitem cererea serverului Google, primim raspunsul si il redirectionam catre userul original.</p>

```python
    print(f"[{curent_date}] Responded with {response_code.name} for \"{packet.question.domain}\"")
    connection.sendto(response_data, address)
```

<p>Afisarea logului pentru server si trimiterea mesajului catre utilizator.</p>