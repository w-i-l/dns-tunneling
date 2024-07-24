<h1>DNS tunneling</h1>
<h2>Transfering a file across multiple DNS queries</h2>
<img src='https://github.com/user-attachments/assets/cea1ef7c-c9be-4f19-a607-9cc1ec7e485e'>



<br>
<hr>
<h2>About it</h2>
<p>Before starting I would recommend checking my previous project <a href="https://github.com/w-i-l/python-dns-server">Python DNS Server</a> as it is a prerequisite for this project. I have modified some functions to allow us transfering a file, so understanding the first project would sure help you understand this one.</p>

<p>So, what is DNS tunneling? DNS tunneling is a technique used to bypass network security measures by encoding data of other programs or protocols in DNS queries and responses. This way, we can transfer data across a network without being detected. This is a very useful technique for penetration testing and for bypassing network restrictions.</p>

>**Note:** This project is for educational purposes only. Many modern OS and ISPs have security measures to prevent DNS tunneling. This project is not intended to be used for malicious purposes.

<p>This project has a client and a server that will allow us to transfer a file across multiple DNS queries. The server will read a file and encode it in DNS queries, and the client will decode the queries and write the file back. The server will send the file in chunks, and the client will receive the chunks and write them to a file.</p>

>**Note**: All the code written below was developed and tested in a Unix environment. If you are using Windows, you may need to make some changes to the code.

<br>
<hr>
<h2>How to use it</h2>
<p>Start the server by running the following command (we need root permisions as the DNS operates on port 53):</p>

```bash
sudo python3 server.py
```

<p>After that you receive a prompt to enter the server IP address. Enter the IP address of the server and press enter. For using the loopback address enter <code>127.0.0.1</code>. The server will start listening for DNS queries.</p>

<p>Now, start the client by running the following command:</p>

```bash
sudo python3 client.py
```

<p>And again you will receive a prompt to enter the server IP address. Enter the IP address of the server and press enter. The client will start sending DNS queries to the server.</p>

<p>You can still use the server as a normal DNS server, the steps for this are provided in the <a href="https://github.com/w-i-l/python-dns-server?tab=readme-ov-file#how-to-use-it">previous project</a>.</p>

<p>For checking if the files have been transfered correctly, you can check the checksum of the files. You can use the <code>md5</code> command for this:</p>

```bash
[ "$(md5 -q files/test.txt)" = "$(md5 -q files/received.txt)" ] && echo "The files are identical." || echo "The files are different."
```

<br>
<hr>
<h2>How it works</h2>
<p>For normal DNS queries, the server work as a normal DNS server. The server will receive a DNS query, parse it, and send a response. The client will send a DNS query, receive a response, and parse it.</p>

<p>For detecting the tunneling, we will only check if the question domain is terminated with <code>DNS_TUNNELING_IDENTIFIER</code>, which for our testing is set to <b>live.tunnel</b>. So in order to receive the <code>test.txt</code> file the question domain should look like this:</p>

>test.txt.example.com.live.tunnel

<p>where the <code>example.com</code> is the domain of the server.</p>

<p>Once the detection has occurred, the server will create empty packages, in which will set the header and the question fields.</p>

<p>The tricky part is at segmenting the file into chunks that can be sent in a DNS query. Below is an exmplanation that should ease the understanding of the process:</p>

```
    The DNS payload is limited to 512 bytes so we need to split the file data into chunks
    As the TXT record is split into chunks of 255 bytes we will split the file data into chunks of 255 bytes
    So if the total length of the file data is 512 bytes we will have maximum 2 chunks

    A TXT chunk will have the following format:
    - 1 byte for the length of the chunk
    - n bytes of data

    As the index can be at most 255 we will use 1 byte for the index
    it will be the last byte of the chunk
```

<p>The index from above comes from the necessity of knowing the order of the chunks. As the UDP protocol does not guarantee the order of the packets, we need to know the order of the chunks so we can reconstruct the file. The index will be the last byte of the chunk, and it will be used to order the chunks. Also this index will help the client reconstruct the file and also avoid a big problem.</p>

<p>For ensuring the deliver of the chucks in right order we will use a <code>stop and wait</code> tehnique. The server will send a chunk and wait for the client to send an acknowledgment. The acknowledgment will be a simple <code>OK</code> message. If the server does not receive the acknowledgment, it will resend the chunk as it has set a timeout.</p>

<p>Once the chuck has been received from the client, it will be kept in a dictionary with the index as the key. This way we solve the issue of receiving the same chuck multiple times, by overwriting the chuck with the same index. Once all the chucks have been received, the server will write the file back, reconstructing them with their indexes.</p>

>**Note**: we have a limit for the file size

 ```
We can only store 255 chunks of data as the index is a byte
So we will store the data in a list and then write it to a file

The maximum size of a TXT record can be up to ~480 bytes
So we can store up to 255 * 480 bytes of data = 122400 bytes = 122.4 KB
```

<br>
<hr>
<h2>Tech specs</h2>
<p>I think that a brief explanation about the segmentation of the file and the implementation of the <code>stop and wait</code> technique is needed as they are the core of the project.</p>

<h3>File segmentation</h3>

```python
packet_data = build_packet()
packet_length = len(packet_data)
```

<p>The <code>build_packet()</code> function will create the header and questions fields for the response packet and will return the packet data. The <code>packet_length</code> will be the length of the packet data. As we will need to calculate the remaining size for the file data.</p>

```python
answear_bytes = b''
answear_bytes += b'\xc0\x0c'
answear_bytes += DNSQuestionType.TXT.value.to_bytes(2, 'big')
answear_bytes += DNSQuestionClass.IN.value.to_bytes(2, 'big')
answear_bytes += (1200).to_bytes(4, 'big') # TTL

answear_length = len(answear_bytes) + 2 # 2 bytes for the length of the rdata
```

<p>The <code>answear_bytes</code> will be the bytes for the answer field of the response packet. The <code>answear_length</code> will be the length of the answer field. Here we just add the boilerplate data for the answer field, and we calculate the length of the answer field.</p>

```python
remaining_bytes = filesize - f.tell() # remaining bytes which can be read
additional_bytes_length = 1 if remaining_bytes <= 255 else 2 # the length bytes for txt data chunks 
file_data_legth = 512 - (packet_length + answear_length + additional_bytes_length + 1) # index byte
```

<p>We calculate the position of the file cursor to determine how many bytes are left to be read. if there are more than 255 bytes left, we will need 2 chucks for the TXT data, meaning that we will need 2 bytes for the length of the TXT data. The <code>file_data_legth</code> will be the length of the file data that can be read and sent in a DNS query.</p>

```python
file_data = f.read(file_data_legth)
file_data_legth = len(file_data) + 1 # 1 byte for the index
file_data = file_data.encode('utf-8')
```

<p>Here we just read and encode the file data and calculate the length of the file data. We add 1 byte for the index of the chunk.</p>

```python
# encoding the length of the rdata
answear_bytes += (file_data_legth + additional_bytes_length).to_bytes(2, 'big')

# encoding file data
max_length = min(255, file_data_legth)

answear_bytes += max_length.to_bytes(1, 'big') # length of the first txt chunk
answear_bytes += file_data[:max_length]
```
<p>We encode the first chuck here. The <code>max_length</code> will be the length of the first chunk. The <code>min</code> function has the role to prevent adding more than 255 bytes in case of a bigger <code>file_data_length</code>.</p>

```python
# second chunk length
max_length = max(0, file_data_legth - 255)

# if there is a second chunk
if max_length > 0:
    answear_bytes += max_length.to_bytes(1, 'big') # length of the second txt chunk
    file_data = file_data[255:] # remove the first chunk
    answear_bytes += file_data[:max_length]
```

<p>For checking id there is another chuck to be sent, we substract the 255 bytes from the <code>file_data_legth</code> which are the bytes that have been sent in the first chuck. If there are more than 0 bytes left, we will send another chuck. We encode the length of the chuck and the data of the chuck.</p>

<h3>Stop and wait</h3>

<p>In a stop and wait tehniques we can encounter 4 situations:</p>
<ol>
    <li>
        <h4>Data loss - <span>the data is lost and the server needs to resend the packet</span></h4>
        <p>This is solved by setting a timeout for the client to acknowledge the packet. If the client does not acknowledge the packet in time, the server will resend the packet.</p>
    </li>
    <li>
        <h4>Acknowledgment loss - <span>the acknowledgment is lost and the server needs to resend the packet</span></h4>
        <p>This is solved by the server when timeouts. If the server does not receive an acknowledgment in time, it will resend the packet.</p>
    </li>
    <li>
        <h4>Packet duplication - <span>the client receives the packet multiple times</span></h4>
        <p>This is solved by the client by overwriting the chunk with the same index. The index will be the last byte of the chunk, and it will be used to order the chunks.</p>
    </li>
    <li>
        <h4>Working scenario - <span>the client receives the packet and sends an acknowledgment</span></h4>
        <p>This is the normal scenario where the client receives the packet, writes the chunk to a file, and sends an acknowledgment to the server.</p>
    </li>
<ol>
<br>

```python
# wait for the client to acknowledge the packet
# if the client does not acknowledge the packet in 50ms resend it
connection.settimeout(1) # 1 second

try:`
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
    connection.sendto(packet, address)
```

<p><b>Notice the <code>connection.settimeout(1)</code> line</b>. This is the timeout for the server to wait for an acknowledgment. If the server does not receive an acknowledgment in 1 second, it will resend the packet. The server will wait for an acknowledgment in a loop, and if it receives an acknowledgment, it will break the loop. If the server receives a <code>RESEND_FLAG</code> message, it will resend the packet.</p>

<p>For the client, the acknowledgment is simple:</p>

```python
# fake packet loss
if random.randint(0, 1) < 0.5:
    # acknowledge the received data
    s.sendto(bytes(RESEND_FLAG, 'utf-8'), (DNS_SERVER_IP, DNS_PORT))
else:
    # acknowledge the received data
    s.sendto(bytes(OK_FLAG, 'utf-8'), (DNS_SERVER_IP, DNS_PORT))
```

<p>The random packet loss is just for testing purposes. The client will send an acknowledgment to the server. If the acknowledgment is <code>OK_FLAG</code>, the server will continue sending packets. If the acknowledgment is <code>RESEND_FLAG</code>, the server will resend the packet.</p>

<p>The testing file content is from <q>Metamorphosis</q> by Franz Kafka, which can be found <a href="https://www.authorama.com/metamorphosis-1.html">here</a>.</p>

<br>
<hr>
<h2>Further reading</h2>
<ul>
    <li><a href="https://www.youtube.com/watch?v=fQ4Y8napHzw">How Does DNS Exfiltration Work?</a></li>
    <li><a href="https://dnstunnel.de/">DNS Tunnel</a></li>
    <li><a href="https://www.youtube.com/watch?v=49F0co_VrTY&t=203s">Bypassing Firewalls with DNS Tunnelling</a></li>
    <li><a href="https://www.baeldung.com/cs/networking-stop-and-wait-protocol">Networking: Stop-and-Wait Protocol</a></li>
    <li><a href="https://github.com/mj2266/stop-and-wait-protocol">Coded stop and wait protocol using python and socket programming</a></li>
</ul>