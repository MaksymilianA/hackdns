FROM centos:latest

RUN yum install -y bash gcc clang gdb valgrind make lldb libstdc++-static

RUN mkdir /hackdns/
RUN mkdir /hackdns/servers/
RUN mkdir /hackdns/dictionaries/
RUN mkdir /hackdns/results/
ADD main.c /hackdns/main.c
ADD Makefile /hackdns/Makefile
ADD dictionaries/common.txt /hackdns/dictionaries/common.txt
ADD dictionaries/common-big.txt /hackdns/dictionaries/common-big.txt
ADD dictionaries/small.txt /hackdns/dictionaries/small.txt
ADD dictionaries/fourchars.txt /hackdns/dictionaries/fourchars.txt
ADD servers/google.conf /hackdns/servers/google.conf
ADD servers/yandex.conf /hackdns/servers/yandex.conf
ADD servers/top10.conf /hackdns/servers/top10.conf
ADD servers/level3.conf /hackdns/servers/level3.conf
ADD servers/au.conf /hackdns/servers/au.conf
ADD servers/br.conf /hackdns/servers/br.conf
ADD servers/ca.conf /hackdns/servers/ca.conf
ADD servers/ch.conf /hackdns/servers/ch.conf
ADD servers/cn.conf /hackdns/servers/cn.conf
ADD servers/co.conf /hackdns/servers/co.conf
ADD servers/de.conf /hackdns/servers/de.conf
ADD servers/fr.conf /hackdns/servers/fr.conf
ADD servers/ir.conf /hackdns/servers/ir.conf
ADD servers/li.conf /hackdns/servers/li.conf
ADD servers/lu.conf /hackdns/servers/lu.conf
ADD servers/pl.conf /hackdns/servers/pl.conf
ADD servers/ro.conf /hackdns/servers/ro.conf
ADD servers/ru.conf /hackdns/servers/ru.conf
ADD servers/sa.conf /hackdns/servers/sa.conf
ADD servers/ua.conf /hackdns/servers/ua.conf
ADD servers/uk.conf /hackdns/servers/uk.conf
ADD servers/us.conf /hackdns/servers/us.conf
ADD servers/za.conf /hackdns/servers/za.conf
RUN cd /hackdns/ && make
RUN ln -s /hackdns/hackdns /bin/hackdns
RUN  debuginfo-install glibc-2.17-196.el7_4.2.x86_64 libgcc-4.8.5-16.el7_4.2.x86_64 -y

ENTRYPOINT ["bash"]