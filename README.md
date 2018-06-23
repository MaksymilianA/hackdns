# hackdns
A high-performance DNS scanner written in C/C++ as a alternative for similar programs written in Python, Perl where huge RAM consumption issue occure for big dictionaries. Created to provide high-performance for small devices and workstations. 

# Requirements
At least GCC 4.9

# Compilation 
Clone the git repository and run `make` command for gcc or `make CC=clang++` for clang. You can use Docker container in Docker/ directory by running `sh ./install.sh` command.

# Usage
```
==========================================
 hackDNS 0.2 - Fast DNS recon for hackers 
==========================================

 Use:
 -d host - Domain name
 -f file - Dictionary file path
 -n file - Path to resolv file where are DNS servers
 -o dir  - Directory path
 -t int  - Number of threads (Default 1)
 -c int  - Number of resolves for a name before giving up (Default 1024)
 -a      - Check A type records (Default A, CNAME, TXT, MX)
 -b      - Check AAAA type records (Default A, CNAME, TXT, MX)
 -s      - Scan ports of A records (EXPERIMENTAL)
 -r      - Scan ports of SPF records (EXPERIMENTAL)
 -e int  - Number of threads for SPF port scanning (Default 1)
 -p      - Specific port to scan (e.g. 22,80,443)
 -i      - Timeout for port scanning in milliseconds (Default 1000ms)
 -m      - Audit SPF records
 -g      - Check host by name enable
 -v      - Verbose mode
 -h      - Show help info
```

# Example
To build friendly environment, go to Docker directory and push

```
$ cd Docker/
```

Install and run bash
```
$ sh ./install.sh
```

If container stopped, start again 
```
$ sh ./start.sh
```

Stop container
```
$ sh ./stop.sh
```

Go to container
```
$ sh ./bash.sh
```

Of course you can skip above step and build hackdns in your local environment. 

```
make
```

Resolve all A, CNAME, MX, TXT records from domains within hackdns.txt using the 100 threads and resolvers within top3.conf. Store the results within output directory:

```
$ ./hackdns -f dictionaries/hackdns.txt -n servers/cloudflare.conf -o ./results/ -d 'domain.com' -t 100
```

Resolve all A records from domains within hackdns.txt using the 100 threads and resolvers within top3.conf in lists and store the results within output directory:

```
$ ./hackdns -f dictionaries/hackdns.txt -n servers/cloudflare.conf -o ./results/ -d 'domain.com' -t 500 -a
```

Resolve all AAAA records from domains within hackdns.txt using the 64 threads and resolvers within top3.conf in lists and store the results within output directory:

```
$ ./hackdns -f dictionaries/hackdns.txt -n servers/cloudflare.conf -o ./results/ -d 'domain.com' -t 64 -b
```

Audit SPF record and get the DNS PTR for all IPs:

```
$ ./hackdns -f dictionaries/spf.txt -n servers/cloudflare.conf -m -g -d 'domain.com'
```

Audit SPF record and get the DNS PTR for all IPs and scan selected ports:

```
$  ./hackdns -f dictionaries/spf.txt -n servers/cloudflare.conf -m -g -p25,80,443,465 -i 2000 -r -e 4 -d 'domain.com'
```


# Contributors
Maksymilian Arciemowicz from https://cxsecurity.com/

