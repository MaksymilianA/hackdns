FROM centos:latest

RUN yum install -y bash gcc clang gdb valgrind make lldb

RUN mkdir /hackdns/
RUN mkdir /hackdns/servers/
RUN mkdir /hackdns/dictionaries/
ADD main.c /hackdns/main.c
ADD Makefile /hackdns/Makefile
ADD dictionaries/common.txt /hackdns/dictionaries/common.txt
ADD dictionaries/fourchars.txt /hackdns/dictionaries/fourchars.txt
ADD servers/google.conf /hackdns/servers/google.conf
ADD servers/yandex.conf /hackdns/servers/yandex.conf
ADD servers/level3.conf /hackdns/servers/level3.conf
ADD servers/nl.conf /hackdns/servers/nl.conf
ADD servers/pl.conf /hackdns/servers/pl.conf
ADD servers/ru.conf /hackdns/servers/ru.conf
ADD servers/us.conf /hackdns/servers/us.conf
ADD servers/top10.conf /hackdns/servers/top10.conf
RUN cd /hackdns/ && make
RUN ln -s /hackdns/hackdns /bin/hackdns

ENTRYPOINT ["bash"]