<h2>Scopul</h2>
<p>Scopul acestui proiect este de a crea un server de DNS care sa poata trimite fisiere de pe server catre client folosind protocolul DNS.</p>
<p>Proiectul este impartit in doua parti: server si client. Serverul va astepta cereri de la clienti si va trimite fisierele cerute, iar clientul va trimite cereri catre server si va primi fisierele cerute.</p>


<h2>O sumarizare</h2>
<a href="https://www.youtube.com/watch?v=fQ4Y8napHzw">DNS Tunnel 100 seconds</a>

<h2>Resurse</h2>
<a href="https://dnstunnel.de/">DNS Tunnel</a>
<a href="https://www.youtube.com/watch?v=49F0co_VrTY&t=203s">video</a>

<h2>Cum sa folosesti</h2>
<p>Se ruleaza intai scriptul de DNS server din <code>dns.py</code> iar apoi scriptul de <code>client.py</code></p>

<h2>Detalii de implementare</h2>
<p>Pentru detectia de tunneling ne vom uita la contentul cerut daca se termina cu identificatorul <code>DNS_TUNNELING_IDENTIFIER</code> care este pentru exemplu nostru <b>live.tunnel</b>.</p>
<p>Pentru a primi fisierul <b>test.txt</b> domeniul nostru va trebui sa arate astfel: <code><b>test.txt</b>.example.com.live.tunnel</code>, unde example.com reprezinta un subdomeniu de care serverul nostru se ocupa.</p>
<p>Aceasta se intampla in <code>dns_answear.py > __find_zone() - linia 290 din fisier</code>. Eroarea este propagata din DNSPacket si tratata in serverul de DNS.</p>
<p>Functia <code>def handle_tunneling(filename: str, address: str, connection: socket.socket):</code> este cea care se ocupa de tunneling. Parametrii acesteia reprezinta: </p>
<ul>
    <li><code>filename</code> - numele fisierului ce va fi partajat</li>
    <li><code>address</code> - adresa de la care se primeste cererea</li>
    <li><code>connection</code> - conexiunea de socket</li>
</ul>
<p>In cazul in care fisierul nu este gasit, se va inchide conexiunea, niciun raspuns DNS fiind oferit.</p>

<h3>Pe partea de server: </h3>
<p>Functia: </p>

```python
 def build_packet() -> bytes:
        header = DNSHeader(create_empty=True)
        header.id = random.randint(0, 65535)
        header.flags = DNSHeaderFlags(
            qr=DNSHeaderQR.RESPONSE,
            opcode=DNSHeaderOPCODE.QUERY,
            aa=DNSHeaderAuthoritiveAnswear.NON_AUTHORITIVE,
            tc=DNSHeaderTruncated.NOT_TRUNCATED,
            rd=DNSHeaderRecursionDesired.NO_RECURSION,
            ra=DNSHeaderRecursionAvailable.NO_RECURSION,
            rcode=DNSHeaderResponseCode.NO_ERROR
        )
        header.questions_count = 1
        header.answers_count = 1
        header.authority_count = 0
        header.additional_count = 0

        question = DNSQuestion(create_empty=True)
        question.domain = filename
        question.qtype = DNSQuestionType.TXT
        question.qclass = DNSQuestionClass.IN

        header_bytes = header.as_bytes()
        question_bytes = question.as_bytes()

        return header_bytes + question_bytes
```
<p>Construieste un pachet gol ce are atribut un ID random si este setat sa primeasca un singur response</p>

```
    The DNS payload is limited to 512 bytes so we need to split the file data into chunks
    As the TXT record is split into chunks of 255 bytes we will split the file data into chunks of 255 bytes
    So if the total length of the file data is 512 bytes we will have maximum 2 chunks

    A chunk will have the following format:
    - 1 byte for the length of the chunk
    - n bytes of data

    As the index can be at most 255 we will use 1 byte for the index
    it will be the last byte of the chunk
```
<p>Cum conexiunea UDP este stateless ne vom folosi de un ID pentru fiecare chunk de text, spre a le diferentia. ID-ul va reprezenta doar numarului chunk-ului din txt.</p>

<p>In partea ce urmeaza vom face calculele necesare pentru determinarea si adaugarea celor doua chuck-uri de text.</p>
    
```python
    try:
        curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
        print(f"[{curent_date}] Waiting for ack")
        while True:
            data, _ = connection.recvfrom(1024)

            curent_date = datetime.strftime(datetime.now(), "%d-%m-%Y %H:%M:%S")
            if data == bytes(OK_FLAG, 'utf-8'):
                print(f"[{curent_date}] Received ack for {filename}")
                break
            elif data == bytes(RESEND_FLAG, 'utf-8'):
                print(f"[{curent_date}] Resending {filename}")
                connection.sendto(packet, address)

    except socket.timeout:
        print(f"[{curent_date}] Resending {filename} - timeout")
        connection.sendto(packet, (address, DNS_PORT))
```
<p>Snippet-ul de mai sus ne ajuta sa realizam o tehnica numita <code>stop and wait</code> prin care ne asiguram ca fiecare pachet UDP a ajuns la destinatie.</p>
<a href="https://www.baeldung.com/cs/networking-stop-and-wait-protocol#bd-stop-and-wait">Reprezentare vizuala</a>
<p>Cat timp nu am primit flag-ul de <code>OK_FLAG</code> vom retrimite pachetul, iar pentru a nu bloca serverul, am configurat conexiune sa aibe un timeout de 50 de ms.</p>

```python
 # send the close flag to the client
    close_flag = bytes(CLOSE_FLAG, 'utf-8')
    connection.sendto(close_flag, address)

    # set the connection to blocking for the next request
    connection.setblocking(True)
    f.close()
```
<p>Dupa ce pachetul a ajuns cu bine, vom trimite un flag de close, pentru a inchide conexiunea, si vom reveni la configuratia initiala a conexiunii, pentru a astepta dupa query-uri in sever.</p>

<p>Pe partea de client:</p>

```python
    @classmethod
    def build_query_packet(cls, domain: str) -> DNSPacket:
        header_flags = DNSHeaderFlags(
            qr=DNSHeaderQR.QUERY,
            opcode=DNSHeaderOPCODE.QUERY,
            aa=DNSHeaderAuthoritiveAnswear.NON_AUTHORITIVE,
            tc=DNSHeaderTruncated.NOT_TRUNCATED,
            rd=DNSHeaderRecursionDesired.NO_RECURSION,
            ra=DNSHeaderRecursionAvailable.NO_RECURSION,
            rcode=DNSHeaderResponseCode.NO_ERROR
        )

        header = DNSHeader(create_empty=True)
        header.id = Client._generate_id()
        header.flags = header_flags
        header.questions_count = 1
        header.answers_count = 0
        header.authority_count = 0
        header.additional_count = 0

        question = DNSQuestion(create_empty=True)
        question.domain = domain
        question.qtype = DNSQuestionType.TXT
        question.qclass = DNSQuestionClass.IN

        answear = DNSAnswear(question)

        packet = DNSPacket(create_empty=True)
        packet.header = header
        packet.question = question
        packet.answears = answear

        return packet
```
<p>Construieste un pachet de query pentru a fi trimis catre server.</p>

```python
     '''
        Receive the data from the server and write it to a file
        We can only store 255 chunks of data as the index is a byte
        So we will store the data in a list and then write it to a file

        The maximum size of a TXT record can be up to ~480 bytes
        So we can store up to 255 * 480 bytes of data = 122400 bytes = 122.4 KB
        '''
        data_d = [None for _ in range(255)]
```

<p>Construim o lista pentru a indexa chuck-urile de date trimise de server si a recompune fisierul.</p>

```python
    while True:
        data, _ = s.recvfrom(1024)

        # if the data is the close flag then we break
        if data == bytes(CLOSE_FLAG, 'utf-8'):
            break
        
        packet = DNSPacket(data, read_answear=True)

        # TXT record data is the data of the answears without the last byte which is the index
        data = packet.answears.data[:-1]
        index = packet.answears.data[-1]
        index = int(index)
        
        data = data.decode('utf-8')
        try:
            data_d[index] = data
        except IndexError: # bigger file than expected
            break
```
<p>Implementam si pe client stop and wait si adaugam fiecare chuck de date la locul potrivit in lista.</p>

```python
    # fake packet loss
    if random.randint(0, 1) < 0.5:
        # acknowledge the received data
        s.sendto(bytes(RESEND_FLAG, 'utf-8'), (LOOPBACK_IP, DNS_PORT))
    else:
        # acknowledge the received data
        s.sendto(bytes(OK_FLAG, 'utf-8'), (LOOPBACK_IP, DNS_PORT))
```
<p>Simulam pierderi de pachete pentru a testa robustetea aplicatiei.</p>

```python
     with open('files/received.txt', 'w+') as f:
        for data in data_d:
            if data:
                f.write(data)
```
<p>La final, scriem datele in fisierul <code>received.txt</code> pentru a le putea vizualiza.</p>