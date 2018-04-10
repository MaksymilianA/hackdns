/*
hackDNS 0.1 - DNS brute force

Copyright (C) 2018, Maksymilian Arciemowicz

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

*/

#include <stdint.h>
#include <stdio.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <string>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>

using namespace std;

///////////////////////////////////////////////////////////////////////////

#define N 4096
#define NUM_OF_ATTEMPS 1024
#define DNS_QUERY_SIZE 2048
#define PROTO_DNS_QTYPE_A 0x0001
#define PROTO_DNS_QTYPE_MX 0x000f
#define PROTO_DNS_QTYPE_TXT 0x0010
#define PROTO_DNS_QTYPE_AAAA 0x001c
#define PROTO_DNS_QTYPE_CNAME 0x0005
#define PROTO_DNS_QTYPE_ANY 0x00ff

static std::vector<std::string> qTypes;

#define PROTO_DNS_QCLASS_IP 0x0001
#define PROTO_DNS_QCLASS_ALL 0x00ff

#if !defined(MSG_NOSIGNAL)
  #define MSG_NOSIGNAL 0x0
#endif

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

static std::mutex mutex;

std::map<int, std::string> g_pages;
std::mutex g_pages_mutex;

///////////////////////////////////////////////////////////////////////////

static unsigned int threats=1, atype=0, debugMode=0, lines=0, podzielone=0;
static string hostname, nsfile, dictionary, resultFile, resultToSave;
static std::vector<std::string> nsVec;
static string dowyjscia;

typedef uint32_t ipv4_t;
typedef unsigned long int       uintptr_tcust;

struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));

struct resolv_entries {
    uint8_t addrs_len;
    ipv4_t *addrs;
};

static uint32_t x, y, z, w;

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int util_strlen(const char *str)
{
    if(str == NULL) return 0;
    int c = 0;

    while (*str++ != 0) c++;
    return c;
}
void util_zero(void *buf, int len)
{
    char *zero = (char*)buf;
    while (len--) *zero++ = 0;
}
static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
     unsigned int jumped = 0, offset;
     *count = 1;
     while(*reader != 0)
     {
         if(*reader >= 192)
         {
             offset = (*reader) * 256 + *(reader+1) - 49152;
             reader = buffer + offset - 1;
             jumped = 1;
         }

         reader = reader+1;
         if(jumped == 0)
             *count = *count + 1;
     }

     if(jumped == 1)
         *count = *count + 1;
}
void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}
void resolv_domain_to_hostname(char *dst_hostname, const char *src_domain)
{
    int len = util_strlen(src_domain) + 1;
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;

    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

uint32_t rand_next(void){
     uint32_t t = x;
     t ^= t << 11;
     t ^= t >> 8;
     x = y; y = z; z = w;
     w ^= w >> 19;
     w ^= t;
     return w;
}
///////////////////////////////////////////////////////////////////////////

void createPacket(struct dnshdr *dnsh, char *query, char *qname, int *query_len, const char *newHost, uint16_t *dns_id, struct dns_question *dnst, int type){

             dnsh = (struct dnshdr *)query;
             qname = (char *)(dnsh + 1);
             resolv_domain_to_hostname(qname, newHost);
             dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
             *query_len = sizeof (struct dnshdr) + util_strlen(qname) + static_cast<int>(1) + sizeof (struct dns_question);

             *dns_id = rand_next() % 0xffff;
             dnsh->id = *dns_id;
             dnsh->opts = htons(1 << 8);
             dnsh->qdcount = htons(1);
             dnst->qtype = htons(type);
             dnst->qclass = htons(PROTO_DNS_QCLASS_ALL);
}


int sendPacket(int *fd, char *query, int *query_len, unsigned int *selectedDns, fd_set *fdset, struct timeval timeo, int *nfds){

             if (send(*fd, query, *query_len, MSG_NOSIGNAL) == -1)
             {
                 if(debugMode) cout << "[resolv] Failed to send packet. Errno: " << errno << " (DNS: " << nsVec[*selectedDns].c_str() << ")" << endl;
                 if (*fd != -1)
                     close(*fd);
                     (*selectedDns)++;
                 return -1;
             }

             fcntl(F_SETFL, *fd, O_NONBLOCK | fcntl(F_GETFL, *fd, 0));
             FD_ZERO(fdset);
             FD_SET(*fd, fdset);

             timeo.tv_sec = 1;
             timeo.tv_usec = 0;
             *nfds = select(*fd + 1, fdset, NULL, NULL, &timeo);

             if (*nfds == -1)
             {
                   if(debugMode) cout << "[resolv] select() failed" << endl;
                   if(*fd != -1)
                       close(*fd);
                   (*selectedDns)++;
                   return -1;
             }
             else if (nfds == 0)
             {
                   if(debugMode) cout << "[resolv] Couldn't resolve (DNS: " << nsVec[*selectedDns].c_str() << ")" << endl;
                   if(*fd != -1)
                       close(*fd);
                   (*selectedDns)++;
                   return -1;
             }

             return 0;
}

int readPacket(int *fd, uint8_t *todel, char *qname, unsigned int *selectedDns,  struct dns_question *dnst, struct dnshdr *dnsh, uint16_t *dns_id, const char *host, int type, std::string &dowyja){
            u_char response[N];
            memset(response,'\0',N);

            int ret = recvfrom(*fd, response,  sizeof (response), MSG_NOSIGNAL, NULL, NULL);
            unsigned char *name;
            struct dnsans *dnsa;
            int stop, i, l, o;
            char outTmp[N];
            uint16_t ancount;

            char dispbuf[N];
            ns_msg msg;

            if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question))){
               if(debugMode) cout << "[recfrom] Failed received ret: " << ret << endl;
               if (*fd != -1)
                   close(*fd);
               (*selectedDns)++;
               return -1;
            }

            dnsh = (struct dnshdr *) response;
            qname = (char *)(dnsh + 1);
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
            name = (unsigned char *)(dnst + 1);

            if (dnsh->id != *dns_id)
            {
               if(debugMode) cout << "[collision] received dns_id is not the same as was sent." << endl;
               if(*fd != -1)
                   close(*fd);
               (*selectedDns)++;
               return -1;
            }

            if (dnsh->ancount == 0)
            {
               return 1;
            }

            struct dns_resource *r_data = NULL;
            resolv_skip_name(name, response, &stop);
            name = name + stop;

            r_data = (struct dns_resource *)name;

            ancount = ntohs(dnsh->ancount);

            ns_initparse(response, r_data->data_len, &msg);
            l = ns_msg_count(msg, ns_s_an);

            for (i = 0; i < ancount; i++)
            {
                ns_rr rr;
                memset(dispbuf,'\0',N);
                ns_parserr(&msg, ns_s_an, i, &rr);

                if(type==PROTO_DNS_QTYPE_MX && rr.type!=PROTO_DNS_QTYPE_MX){
                    continue;
                }
                if(type==PROTO_DNS_QTYPE_TXT && rr.type!=PROTO_DNS_QTYPE_TXT){
                    continue;
                }

                ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
                memset(outTmp,'\0',N);
                snprintf(outTmp, N, "\t%s\n", dispbuf);
                cout << outTmp;

                dowyja += outTmp;

            }


            return 0;
}

int connectToDnsServer(int *fd, unsigned int *selectedDns, struct sockaddr_in addr, const char *dnsserv){

             util_zero(&addr, sizeof (struct sockaddr_in));
             addr.sin_family = AF_INET;
             inet_aton(dnsserv, &addr.sin_addr);
             addr.sin_port = htons(53);

             if(*fd != -1) close(*fd);

             if ((*fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
             {
                 if(debugMode) cout << "[socket] Failed to create socket (DNS: " << dnsserv << ")" << endl;
                 (*selectedDns)++;
                 return -1;
             }

             if (connect(*fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
             {
                 if(debugMode) cout << "[connect] Failed to call connect on udp socket (DNS: " <<  dnsserv << ")" << endl;
                 if(*fd != -1)
                     close(*fd);
                 (*selectedDns)++;
                 return -1;

             }
             return 0;
}

int startCore(int idxServDns)
{
     rand_init();

     unsigned int selectedDns= idxServDns, thNum=selectedDns;

     char query[DNS_QUERY_SIZE];
     char failed=0;
     char *qname;
     string dowyja;

     uint8_t response[DNS_QUERY_SIZE];

     struct dnshdr *dnsh;
     struct sockaddr_in addr = {0};
     struct dns_question *dnst;
     struct timeval timeo;

     const int wylicz=(int)((long)selectedDns*podzielone), consthread=idxServDns;
     int wyliczUp=(int)(((long)selectedDns*podzielone)+podzielone);
     int ilin=0, query_len, fd = -1, i = 0, nfds, selectedDnsTmp, tries;
     uint16_t dns_id;
     fd_set fdset;
     string linex;
     ifstream mydict (dictionary);

     //////////////////////////////////////////////////////////////

     if((long)selectedDns==(threats-1)){ // LAST THREAD
          wyliczUp=lines;
     }

     ///// BACK HERE IF DNS SERVER FAIL AND CHANGE DNS
     establishConnectionDNServer:
     if(selectedDns>=nsVec.size()){
         selectedDnsTmp=selectedDns/nsVec.size();
         selectedDns=selectedDns-(selectedDnsTmp*(nsVec.size()));
     }
     if( NUM_OF_ATTEMPS < tries++ ) {
        if(debugMode) cout << "WARNING: Couldn't check the " << linex << "\n" << endl;
        failed=0; ilin++; tries=1;
     }

     if(connectToDnsServer(&fd, &selectedDns, addr, nsVec[selectedDns].c_str()) == -1){
         goto establishConnectionDNServer;
     }

     if (mydict.is_open()){
          for (; ilin < wyliczUp; ilin++){

              if(wylicz<=ilin){

                 if(failed==0){
                    getline (mydict,linex);
                    lecisziom:
                    if(linex.length()!=0)
                        linex += ".";
                    linex += hostname;
                 } else {
                    if(failed==1){ failed = 0; goto gotoarec; }
                    else if(failed==2){ failed = 0; goto gotomxrec; }
                    else if(failed==3){ failed = 0; goto gototxtrec; }
                    failed = 0;
                 }

                 if(linex.length()==0) { continue; }

                 // A TYPE
                 gotoarec:
                 memset(query,'\0',DNS_QUERY_SIZE);
                 createPacket(dnsh, query, qname, &query_len, linex.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_A);
                 if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                       failed=1; goto establishConnectionDNServer;
                  };
                 if (FD_ISSET(fd, &fdset))
                 {
                     if(readPacket(&fd, response, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_A, dowyja)==-1){
                           failed=1; goto establishConnectionDNServer;
                      };
                 } else { selectedDns++; failed=1; goto establishConnectionDNServer; }

                 if(atype==1) { tries=0; continue; }

                 // MX TYPE
                 gotomxrec:
                 memset(query,'\0',DNS_QUERY_SIZE);
                 createPacket(dnsh, query, qname, &query_len, linex.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_MX);
                 if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                       failed=2; goto establishConnectionDNServer;
                  };
                 if (FD_ISSET(fd, &fdset))
                 {
                     if(readPacket(&fd, response, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_MX, dowyja)==-1){
                           failed=2; goto establishConnectionDNServer;
                      };
                 } else { selectedDns++; failed=2; goto establishConnectionDNServer; }

                 // TXT TYPE
                 gototxtrec:
                 memset(query,'\0',DNS_QUERY_SIZE);
                 createPacket(dnsh, query, qname, &query_len, linex.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_TXT);
                 if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                       failed=3; goto establishConnectionDNServer;
                  };
                 if (FD_ISSET(fd, &fdset))
                 {
                     if(readPacket(&fd, response, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_TXT, dowyja)==-1){
                           failed=3; goto establishConnectionDNServer;
                      };
                 } else { selectedDns++; failed=3; goto establishConnectionDNServer; }
                 tries=0;
              } else {
                    mydict.ignore(1024, mydict.widen('\n'));
              }
          }
      } else {
          if(debugMode) cout << "\nERROR: Can not open dictionary file :( \n\n" << endl;
      }
      mydict.close();
      g_pages_mutex.lock();
      g_pages[consthread] = dowyja;
      g_pages_mutex.unlock();
      return 0;
}


void *dziecko(void *arg) {
    const int param=(int)((long)arg);
    startCore(param);
    return 0;
}

void help(char *prog)
{
    cout << " Use:" << endl;
    cout << " -d host - Domain name" << endl;
    cout << " -f file - Dictionary file path" << endl;
    cout << " -n file - Path to resolv file where are DNS servers" << endl;
    cout << " -o dir  - Directory path" << endl;
    cout << " -t int  - Number of threats. (Default 1)" << endl;
    cout << " -a      - Only find subdomains" << endl;
    cout << " -v      - Verbose mode\n" << endl;
    cout << " example: " << prog << " -f dictionaries/dnssubminer.txt -n servers/yandex.conf -o ./results/ -d domain.com -t 64\n" << endl;
}

int main( int argc , char *argv[])
{
    int opt, idx;
    int huy=0, index=0, errorcode=0;

    cout << "\n==========================================\n hackDNS 0.1 - Fast DNS recon for hackers \n==========================================\n" << endl;

    while((opt = getopt(argc, argv, "d:n:f:o:t:avh")) != -1) {
       switch(opt){
       case 'd' :
           hostname = optarg;
           break;
       case 'n' :
           nsfile = optarg;
           break;
       case 'f' :
           dictionary = optarg;
           break;
       case 'o' :
           resultFile = optarg;
           break;
       case 't' :
           threats=atoi(optarg);
           break;
       case 'a' :
           atype=1;
           break;
       case 'v' :
           debugMode=1;
           break;
       case 'h' :
           help(argv[0]);
           return 0;
           break;
       }
    }

    if(!hostname.length()){
       help(argv[0]);
       cout << "ERROR: Hostname not defined.\n" << endl;
       return -1;
    }

    if(resultFile.length()!=0){
      resultFile += hostname;
      resultFile += ".";
      resultFile += to_string((int)time(NULL));
      resultFile += ".txt";
    }

    if(!dictionary.length()){
       dictionary = "./dictionary/jhaddix.txt";
    }

    // The size of dictionary
    ifstream mydict (dictionary);
    if(!mydict){ cout << "\nCRITICAL: Wrong path to dictionary file\n" << endl; return -1; }
    while(mydict.ignore(1024, mydict.widen('\n'))) lines++;
    mydict.close();

    // Records to check per thread
    podzielone=lines/threats;

    string nsentry;
    ifstream myns2 (nsfile);
    if(!myns2){ cout << "\nCRITICAL: Wrong path to resolver file\n" << endl; return -1; }
    while(getline (myns2,nsentry)){
          nsVec.push_back(nsentry.c_str());
    }
    myns2.close();

    pthread_t thread_id[threats];

    for(idx=0; idx < threats; idx++)
    {
        if((errorcode=pthread_create( &thread_id[idx], NULL, dziecko, (void *)(uintptr_tcust)(idx)))!=0){
           cout << "ERROR: Can't create thread " << idx << ". Scan will be incomplete. Use lower value or try optimize your OS. Error code: " << errorcode << endl;
           sleep(5);
           threats=idx;
           break;
       };
    }

    for(idx=0; idx < threats; idx++)
    {
       pthread_join( thread_id[idx], NULL);
    }

    if(resultFile.length()!=0){
        std::ofstream outfile (resultFile.c_str());
        g_pages_mutex.lock();
        for (const auto &pair : g_pages) {
            outfile << pair.second << std::endl;
        }
        g_pages_mutex.unlock();
        outfile.close();
    }

    return 0;
}