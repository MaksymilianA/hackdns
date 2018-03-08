# hackdns
Fast DNS scanner is written in C to eliminate huge RAM consumption when brute forcing DNS with a huge dictionary and to provide maximum performance. Easy, Fast and Linux compatibility.

Scope default: A, CNAME, MX, TXT records
Scope fast (parameter -a): A, CNAME

Example configuration:
Centos 7:
- CPU 1vCore 1GB RAM 
- threads: 500

Result:
- Outgoint DNS traffic: 3.9MBit/s
- Incoming DNS traffic: 8.1MBit/s

No issue noticed with big dictionaries. 
