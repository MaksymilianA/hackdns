FROM centos:latest

RUN yum install -y bash gcc clang gdb valgrind make lldb libstdc++-static

RUN mkdir /hackdns/
RUN mkdir /hackdns/servers/
RUN mkdir /hackdns/dictionaries/
RUN mkdir /hackdns/results/
ADD main.c /hackdns/main.c
ADD Makefile /hackdns/Makefile
ADD dictionaries/ /hackdns/dictionaries/
ADD servers/ /hackdns/servers/
RUN cd /hackdns/ && make
RUN ln -s /hackdns/hackdns /bin/hackdns
#RUN  debuginfo-install glibc-2.17-196.el7_4.2.x86_64 libgcc-4.8.5-16.el7_4.2.x86_64 -y

ENTRYPOINT ["bash"]
