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

using namespace std;

///////////////////////////////////////////////////////////////////////////

#define N 4096
#define BUFFSIZE_HOST 1024
#define DNS_QUERY_SIZE 2048
#define PROTO_DNS_QTYPE_A 1
#define PROTO_DNS_QCLASS_IP 1
#define PROTO_TCP_OPT_NOP 1
#define PROTO_TCP_OPT_MSS 2
#define PROTO_TCP_OPT_WSS 3
#define PROTO_TCP_OPT_SACK 4
#define PROTO_TCP_OPT_TSVAL 8

#if !defined(MSG_NOSIGNAL)
   #define MSG_NOSIGNAL 0x0
#endif

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

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
int util_strlen(const char *str)
{
  if(str==NULL) return 0;
  int c = 0;

  while (*str++ != 0)
      c++;
  return c;
}
void util_zero(void *buf, int len)
{
  char *zero = (char*)buf;
  while (len--)
      *zero++ = 0;
}
static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
  unsigned int jumped = 0, offset;
  *count = 1;
  while(*reader != 0)
  {
      if(*reader >= 192)
      {
          offset = (*reader)*256 + *(reader+1) - 49152;
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


int niskiPoziom3(void *idxServDns)
{
  rand_init();

  unsigned int selectedDns= static_cast<unsigned int>(reinterpret_cast<uintptr_tcust>(idxServDns));
  unsigned int thNum=selectedDns;

  char outTmp[N];
  char query[DNS_QUERY_SIZE];
  char failed=0;
  char *qname;

  uint8_t response[DNS_QUERY_SIZE];

  struct resolv_entries *entries;
  struct dnshdr *dnsh;
  struct sockaddr_in addr = {0};
  struct dns_question *dnst;
  struct timeval timeo;
  int query_len;
  int fd = -1, i = 0;
  int nfds;
  int selectedDnsTmp;

  uint16_t dns_id;

  fd_set fdset;

  //////////////////////////////////////////////////////////////

  const int wylicz=(int)((long)selectedDns*podzielone);
  int wyliczUp=(int)(((long)selectedDns*podzielone)+podzielone);
  int ilin=0;

  if((threats-1)==(long)selectedDns){
       wyliczUp=lines;
  }

  string linex;
  ifstream mydict (dictionary);

  ///// BACK HERE IF DNS SERVER FAIL AND CHANGE DNS
  establishConnectionDNServer:
  if(selectedDns>=nsVec.size()){
      selectedDnsTmp=selectedDns/nsVec.size();
      selectedDns=selectedDns-(selectedDnsTmp*(nsVec.size()));
  }

  util_zero(&addr, sizeof (struct sockaddr_in));
  addr.sin_family = AF_INET;
  inet_aton(nsVec[selectedDns].c_str(), &addr.sin_addr);
  addr.sin_port = htons(53);

  if (fd != -1) close(fd);

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
  {
      if(debugMode) printf("[socket] Failed to create socket (DNS: %s)\n",nsVec[selectedDns].c_str());
      selectedDns++;
      goto establishConnectionDNServer;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
  {
     if(debugMode) printf("[connect] Failed to call connect on udp socket (DNS: %s)\n",nsVec[selectedDns].c_str());
      if (fd != -1)
          close(fd);
      selectedDns++;
      goto establishConnectionDNServer;
  }

  if (mydict.is_open()){
       for (; ilin < wyliczUp; ilin++){

           if(wylicz<=ilin){

              if(failed==0){
                   getline (mydict,linex);
                   lecisziom:
                   linex += ".";
                   linex += hostname;
              } else { failed = 0; }

              memset(query,'\0',DNS_QUERY_SIZE);

              if(entries) free(entries);

              entries = (struct resolv_entries*)calloc(1, sizeof (struct resolv_entries));
              dnsh = (struct dnshdr *)query;
              qname = (char *)(dnsh + 1);
              resolv_domain_to_hostname(qname, linex.c_str());
              dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
              query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);


   //////////////////////////////////////////////////////////
              dns_id = rand_next() % 0xffff;
              dnsh->id = dns_id;
              dnsh->opts = htons(1 << 8);
              dnsh->qdcount = htons(1);
              dnst->qtype = htons(PROTO_DNS_QTYPE_A);
              dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

              if (send(fd, query, query_len, MSG_NOSIGNAL) == -1)
              {
                  failed=1;
                  if(debugMode) printf("[resolv] Failed to send packet: %d (DNS: %s)\n", errno,nsVec[selectedDns].c_str());
                  if (fd != -1)
                      close(fd);
                  selectedDns++;
                  goto establishConnectionDNServer;
              }

              fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));
              FD_ZERO(&fdset);
              FD_SET(fd, &fdset);

              timeo.tv_sec = 1;
              timeo.tv_usec = 0;
              nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

              if (nfds == -1)
              {
                  failed=1;
                  if(debugMode) printf("[resolv] select() failed\n");
                  if (fd != -1)
                      close(fd);
                  selectedDns++;
                  goto establishConnectionDNServer;
              }
              else if (nfds == 0)
              {
                 failed=1;
                 if(debugMode) printf("[resolv] Couldn't resolve %s (DNS: %s)\n", linex.c_str(), nsVec[selectedDns].c_str());
                  if (fd != -1)
                      close(fd);
                  selectedDns++;
                  goto establishConnectionDNServer;
              }
              else if (FD_ISSET(fd, &fdset))
              {

                  int ret = recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);
                  unsigned char *name;
                  struct dnsans *dnsa;
                  uint16_t ancount;
                  int stop;

                  if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question))){
                          failed=1;
                          if(debugMode) printf("[recfrom] Failed received ret: %i\n", ret);
                          if (fd != -1)
                              close(fd);
                          selectedDns++;
                          goto establishConnectionDNServer;
                  }

                  dnsh = (struct dnshdr *)response;
                  qname = (char *)(dnsh + 1);
                  dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
                  name = (unsigned char *)(dnst + 1);

                  if (dnsh->id != dns_id)
                  {
                      failed=1;
                      if(debugMode) printf("[collision] received dns_id is not the same as was sent.\n");
                      if (fd != -1)
                          close(fd);
                      selectedDns++;
                      goto establishConnectionDNServer;
                  }

                  if (dnsh->ancount == 0)
                  {
                      continue;
                  }

                  ancount = ntohs(dnsh->ancount);
                  while (ancount-- > 0)
                  {
                      struct dns_resource *r_data = NULL;

                      resolv_skip_name(name, response, &stop);
                      name = name + stop;

                      r_data = (struct dns_resource *)name;
                      name = name + sizeof(struct dns_resource);

                      if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
                      {
                          if (ntohs(r_data->data_len) == 4)
                          {
                              uint8_t tmp_buf[4];
                              for(i = 0; i < 4; i++){
                                  tmp_buf[i] = name[i];
                              }

                              entries->addrs = (ipv4_t *)realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                              snprintf(outTmp, N, "\t%s\t%i.%i.%i.%i\t\n", linex.c_str(), tmp_buf[0],tmp_buf[1],tmp_buf[2],tmp_buf[3]);
                              printf("%s",outTmp);
                              dowyjscia+=outTmp;
                          }

                          name = name + ntohs(r_data->data_len);
                      } else {
                          resolv_skip_name(name, response, &stop);
                          name = name + stop;
                      }
                  }
              }
           } else {
                 mydict.ignore(1024, mydict.widen('\n'));
           }
       }
   } else {
       if(debugMode) printf("\nERROR: Can not open dictionary file :( \n\n");
   }
   mydict.close();
   return 0;
}



int takeOverCname(const char *host)
{
char outTmp[N];

u_char nsbuf[N];
int l, o;
    
goconlyrecord:
l = res_search(host, ns_c_in, ns_t_cname, nsbuf, sizeof(nsbuf));
if(TRY_AGAIN==h_errno) goto goconlyrecord;

if (l >= 0) {
    goconlyrecordsec:
    o = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
    if(TRY_AGAIN==h_errno) goto goconlyrecordsec;

    if (o < 0) {
         memset(outTmp,'\0',N);
         snprintf(outTmp, N, " Possible to take over CNAME record for domain %s\n", host);
         printf("%s",outTmp);
         //dowyjscia += outTmp;
    }
}
return 0;
}

int checkArecord(const char *host)
{
u_char nsbuf[N];
char dispbuf[N];
ns_msg msg;
ns_rr rr;
int l;

char outTmp[N];

goaonlyrecord:
l = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
if(TRY_AGAIN==h_errno) goto goaonlyrecord;

if (l >= 0) {
          ns_initparse(nsbuf, l, &msg);
          l = ns_msg_count(msg, ns_s_an);
          if(0<l) {
                        memset(dispbuf,'\0',N);
                        ns_parserr(&msg, ns_s_an, 0, &rr);
                        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));

                        memset(outTmp,'\0',N);
                        snprintf(outTmp, N, "\t%s\n", dispbuf);
                        printf("%s",outTmp);
                        //dowyjscia += outTmp;
          }
}
return 0;
}

int generalCheck(const char *host)
{
char outTmp[N];
char dispbuf[N];
u_char nsbuf[N];

ns_msg msg;
ns_rr rr;
int i, l;

memset(nsbuf,'\0',N);

// A RECORD
goarecord:
l = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
if(TRY_AGAIN==h_errno) goto goarecord;

if (l >= 0) {
          ns_initparse(nsbuf, l, &msg);
          l = ns_msg_count(msg, ns_s_an);

          for (i = 0; i < l; i++)
          {
                memset(dispbuf,'\0',N);
                ns_parserr(&msg, ns_s_an, i, &rr);
                ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));

                memset(outTmp,'\0',N);
                snprintf(outTmp, N, "\t%s\n", dispbuf);
                printf("%s",outTmp);
                //dowyjscia += outTmp;
          }
}

memset(nsbuf,'\0',N);

// MX RECORD
gomxarecord:
l = res_query(host, ns_c_in, ns_t_mx, nsbuf, sizeof(nsbuf));
if(TRY_AGAIN==h_errno) goto gomxarecord;

if (l >= 0) {

          ns_initparse(nsbuf, l, &msg);
          l = ns_msg_count(msg, ns_s_an);

          for (i = 0; i < l; i++)
          {
                ns_parserr(&msg, ns_s_an, i, &rr);
                if(rr.type!=ns_t_mx){
                   continue;
                }
                ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
                memset(outTmp,'\0',N);
                snprintf(outTmp, N, "\t%s\n", dispbuf);
                printf("%s",outTmp);
                //dowyjscia += outTmp;
          }
}

memset(nsbuf,'\0',N);

gotxtrecord:
// TXT
l = res_query(host, ns_c_in, ns_t_txt, nsbuf, sizeof(nsbuf));
if(TRY_AGAIN==h_errno) goto gotxtrecord;

if (l >= 0) {
    ns_initparse(nsbuf, l, &msg);
    l = ns_msg_count(msg, ns_s_an);
    for (i = 0; i < l; i++)
    {
          ns_parserr(&msg, ns_s_an, i, &rr);
          if(rr.type!=ns_t_txt){
               continue;
          }
          ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));

          memset(outTmp,'\0',N);
          snprintf(outTmp, N, "\t%s\n", dispbuf);
          printf("%s",outTmp);
          //dowyjscia += outTmp;
    }
}

return 0;
}


void *thread(void *arg) {

char *ret;

if(atype!=3){
    const int wylicz=(int)((long)arg*podzielone);
    int wyliczUp=(int)(((long)arg*podzielone)+podzielone);
    int i;
    string linex;
    
    if((threats-1)==(long)arg){
       wyliczUp=lines;
    }
    
    ifstream mydict (dictionary);

    if (mydict.is_open()){
       for (i = 0; i < wyliczUp; i++){

           if(wylicz<=i){
               getline (mydict,linex);
               linex += ".";
               linex += hostname;

               if(atype==1){
                   checkArecord(linex.c_str());
               }
               else if(atype==2){
                   takeOverCname(linex.c_str());
               } else {
                   generalCheck(linex.c_str());
               }
           } else {
                 mydict.ignore(1024, mydict.widen('\n'));
           }
       }
   }
   mydict.close();
} else {
    niskiPoziom3(arg);
}
pthread_exit(ret);
}

void help(char *prog)
{
 printf(" Use: \n");
 printf(" -d host - Domain name\n");
 printf(" -f file - Dictionary file path\n");
 printf(" -n file - Path to resolv file where are DNS servers\n");
 printf(" -o dir  - Directory path\n");
 printf(" -t int  - Number of threats. (Default 1)\n");
 printf(" -a      - Only find subdomains \n");
 printf(" -c      - Search CNAME to takeover \n");
 printf(" -x      - Search A,CNAME and bypass local resolver (direct DNS calls) \n");
 printf(" -v      - Verbose mode \n\n");
 printf(" example: %s -f dictionaries/dnssubminer.txt -n servers/yandex.conf -o ./results/ -d domain.com -t 64\n\n",prog);
}

int main( int argc , char *argv[])
{
int opt, idx;
int huy=0, index=0, errorcode=0;

printf("\n==========================================\n hackDNS 0.1 - Fast DNS recon for hackers \n==========================================\n\n");

while((opt = getopt(argc, argv, "d:n:f:o:t:acxvh")) != -1) {
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
    case 'c' :
        atype=2;
        break;
    case 'x' :
        atype=3;
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
    printf("ERROR: Hostname not defined.\n\n");
    return -1;
}

if(resultFile.length()!=0){
   resultFile += hostname;
   resultFile += ".";
   resultFile += to_string((int)time(NULL));
   resultFile += ".txt";
}
if(!dictionary.length()){
    dictionary = "./dictionary/common.txt";
}

// The size of dictionary
ifstream mydict (dictionary);
if(!mydict){ printf("\nCRITICAL: Wrong path to dictionary file\n\n"); return -1; }
while(mydict.ignore(1024, mydict.widen('\n'))) lines++ ;
mydict.close();

// Records to check per thread
podzielone=lines/threats;

string nsentry;
ifstream myns2 (nsfile);
if(!myns2){ printf("\nCRITICAL: Wrong path to resolver file\n\n"); return -1; }
while(getline (myns2,nsentry)){
       nsVec.push_back(nsentry.c_str());
}
myns2.close();

if(atype!=3){
    res_init();
    _res.nscount=0;
    for(huy=0;huy<nsVec.size();huy++){
        if(MAXNS<=huy) break;
        _res.nscount++;
        _res.nsaddr_list[huy].sin_family = AF_INET;
        _res.nsaddr_list[huy].sin_addr.s_addr = inet_addr(nsVec[huy].c_str());
        _res.nsaddr_list[huy].sin_port = htons(53);
    }
    if(atype==1){
       checkArecord(hostname.c_str());
    }else if(atype==2){
       takeOverCname(hostname.c_str());
    }else if(atype==0){
       generalCheck(hostname.c_str());
    }

}
    
    
pthread_t thread_id[threats];

for(idx=0; idx < threats; idx++)
{
    if((errorcode=pthread_create( &thread_id[idx], NULL, thread, (void *)(uintptr_tcust)(idx)))!=0){
        printf("ERROR: Can't create thread %i. Scan will be incomplete. Use lower value or try optimize your OS. Error code: %i\n", idx, errorcode);
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
   outfile << dowyjscia << std::endl;
   outfile.close();
}

return 0;
}

