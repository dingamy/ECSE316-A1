**Compilation**

To compile the client, run:

javac DNSClient.java

**Usage**

Run with the java command and specify flags, the DNS server, and the domain name.

**Examples**

Query the IP address (A record) of www.mcgill.ca using McGill’s DNS server:

java DNSClient @132.206.85.18 www.mcgill.ca

Query the mail server (MX record) for mcgill.ca using Google’s public DNS server, with a 10-second timeout and at most 2 retries:

java DNSClient -t 10 -r 2 -mx @8.8.8.8 mcgill.ca

**Environment**

This project was compiled and tested with:

java version "21.0.4" 2024-07-16 LTS  
javac 21.0.4  
Java(TM) SE Runtime Environment (build 21.0.4+8-LTS-274)  
Java HotSpot(TM) 64-Bit Server VM (build 21.0.4+8-LTS-274, mixed mode, sharing)  
