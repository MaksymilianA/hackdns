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

RUN yum install centos-release-scl-rh -y
RUN yum install devtoolset-3-gcc devtoolset-3-gcc-c++ -y
RUN update-alternatives --install /usr/bin/gcc-4.9 gcc-4.9 /opt/rh/devtoolset-3/root/usr/bin/gcc 10
RUN update-alternatives --install /usr/bin/g++-4.9 g++-4.9 /opt/rh/devtoolset-3/root/usr/bin/g++ 10

#RUN mv /usr/bin/g++ /usr/bin/g++-old
RUN ln -s /opt/rh/devtoolset-3/root/usr/bin/g++ /usr/local/bin/g++
RUN cd /hackdns/ && make
RUN ln -s /hackdns/hackdns /bin/hackdns
#RUN  debuginfo-install glibc-2.17-196.el7_4.2.x86_64 libgcc-4.8.5-16.el7_4.2.x86_64 -y

ENTRYPOINT ["bash"]


