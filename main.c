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

using namespace std;

#define N 4096
#define BUFFSIZE_HOST 1024
#define MAX_DNS_SERVERS 1024
#define DNS_QUERY_SIZE 2048
#define FILENAME_SIZE_RESULT 1024

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0x0
#endif

static char hostname[BUFFSIZE_HOST+1];
static char nsfile[BUFFSIZE_HOST+1];
static char dictionary[BUFFSIZE_HOST+1];
static unsigned int definedDnsServers=0;
static unsigned int threats=1;
static unsigned int podzielone;
static unsigned int atype=0;
static unsigned int debugMode=0;
static string resultFile;

static char *dnservers[MAX_DNS_SERVERS];

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

typedef uint32_t ipv4_t;
typedef unsigned long int       uintptr_t;

#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1
#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

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

void rand_init(void)
{
   x = time(NULL);
   y = getpid() ^ getppid();
   z = clock();
   w = z ^ y;
}

void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
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

uint32_t rand_next(void) //period 2^96-1
{
   uint32_t t = x;
   t ^= t << 11;
   t ^= t >> 8;
   x = y; y = z; z = w;
   w ^= w >> 19;
   w ^= t;
   return w;
}
static uint32_t balancuj= 1;

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))



int niskiPoziom3(void *idxServDns)
{
   rand_init();

   string dowyjscia;

   unsigned int selectedDns= static_cast<unsigned int>(reinterpret_cast<uintptr_t>(idxServDns));
   unsigned int thNum=selectedDns;
   unsigned int index = 0, skip=0;

   const unsigned int lowOffset=(selectedDns) * (podzielone);
   const unsigned int wylicz=podzielone+(int)lowOffset;

   char line[BUFFSIZE_HOST], ch;
   char outTmp[N];
   char newhostname[BUFFSIZE_HOST+1];
   char query[DNS_QUERY_SIZE];
   char failed=0;

   char *qname;

   memset(newhostname,'\0',sizeof(newhostname));

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

   FILE *fp = fopen ( dictionary, "r");
   if(!fp){
     if(debugMode) printf("\nERROR: Can not open dictionary file :( \n\n");
     return -2;
   }

   establishConnectionDNServer:
   if(selectedDns>=definedDnsServers){
       selectedDnsTmp=selectedDns/definedDnsServers;
       selectedDns=selectedDns-(selectedDnsTmp*definedDnsServers);
   }

   util_zero(&addr, sizeof (struct sockaddr_in));
   addr.sin_family = AF_INET;
   inet_aton(dnservers[selectedDns], &addr.sin_addr);
   addr.sin_port = htons(53);

   if (fd != -1)
       close(fd);

   if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
   {
       if(debugMode) printf("[socket] Failed to create socket\n");
       selectedDns++;
       goto establishConnectionDNServer;
   }

   if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
   {
      if(debugMode) printf("[connect] Failed to call connect on udp socket\n");
       if (fd != -1)
           close(fd);
       selectedDns++;
       goto establishConnectionDNServer;
   }


   if(strlen(line)>0) goto lecisziom;
   index=0;

   while ( failed==1 | (int)(ch = getc ( fp )) != EOF ) {
       if(wylicz<skip) break;
       if ( failed==0 & ch != '\n' && index<(BUFFSIZE_HOST-1)){
           line[index++] = ch;
       }else {
           if(failed==1){ failed=0;}
           else
               line[index] = '\0';

           memset(query,'\0',DNS_QUERY_SIZE);
           if((skip++)>=lowOffset){
               lecisziom:
               snprintf(newhostname, BUFFSIZE_HOST, "%s.%s", line, hostname);

           if(entries) free(entries);

           entries = (struct resolv_entries*)calloc(1, sizeof (struct resolv_entries));
           dnsh = (struct dnshdr *)query;
           qname = (char *)(dnsh + 1);
           resolv_domain_to_hostname(qname, newhostname);

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
               if(debugMode) printf("[resolv] Failed to send packet: %d\n", errno);
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
               if(debugMode) printf("[resolv] select() failed\n");
               if (fd != -1)
                   close(fd);
               selectedDns++;
               goto establishConnectionDNServer;
           }
           else if (nfds == 0)
           {
              if(debugMode) printf("[resolv] Couldn't resolve %s\n", newhostname);
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
                   if(debugMode) printf("[collision] received dns_id is not the same as was sent.\n");
                   if (fd != -1)
                       close(fd);
                   selectedDns++;
                   goto establishConnectionDNServer;
               }

               if (dnsh->ancount == 0)
               {
                   index=0;
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
                           snprintf(outTmp, N, "\t%s\t%i.%i.%i.%i\t\n", newhostname, tmp_buf[0],tmp_buf[1],tmp_buf[2],tmp_buf[3]);
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
     }
     index=0;
    }}

   if(resultFile.length()!=0){
        FILE *f;
        f = fopen(resultFile.c_str(), "a");
        if (f == NULL)
        {
              printf("ERROR: Error opening file to output!\n");
              exit(1);
        }
        fprintf(f, "%s",dowyjscia.c_str());
        fclose(f);
    }
    close(fd);
    return 0;
}


int takeOverCname(char *host)
{
 char outTmp[N];
 string dowyjscia;

 u_char nsbuf[N];
 int i, l, o;
 l = res_search(host, ns_c_in, ns_t_cname, nsbuf, sizeof(nsbuf));

 if (l >= 0) {
     o = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
     if (o < 0) {
          memset(outTmp,'\0',N);
          snprintf(outTmp, N, " Possible to take over CNAME record for domain %s\n", host);
          printf("%s",outTmp);
          dowyjscia = outTmp;
     }
 }

 if(resultFile.length()!=0){
        FILE *f;
        f = fopen(resultFile.c_str(), "a");
        if (f == NULL)
        {
              printf("ERROR: Error opening file to output!\n");
              exit(1);
        }
        fprintf(f, "%s",dowyjscia.c_str());
        fclose(f);
 }

 return 0; 
}

int checkArecord(char *host)
{
 u_char nsbuf[N];
 char dispbuf[N];
 ns_msg msg;
 ns_rr rr;
 int i, l;
 string dowyjscia;

 char outTmp[N];
 char *outResult;
 size_t outResultOffset;

 l = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
      
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
                         dowyjscia = outTmp;
                   }
 }

 FILE *f;
 f = fopen(resultFile.c_str(), "a");

 if (f == NULL)
 {
       printf("x ERROR: Error opening file to output! %s\n",resultFile.c_str());
       exit(1);
 }
 fprintf(f, "%s",dowyjscia.c_str());
 fclose(f);

 return 0;
}

int generalCheck(char *host)
{
 char outTmp[N];
 char dispbuf[N];
 u_char nsbuf[N];

 string dowyjscia;

 ns_msg msg;
 ns_rr rr;
 int i, l, o;

 // A RECORD
 l = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
      
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
                 printf("d %s",outTmp);
                 dowyjscia = outTmp;
           }
 }

 // CNAME
/*  l = res_query(host, ns_c_in, ns_t_cname, nsbuf, sizeof(nsbuf));
 if (l >= 0) {
     ns_initparse(nsbuf, l, &msg);
     l = ns_msg_count(msg, ns_s_an);
     return 0;
 }
*/

 // MX RECORD
 l = res_query(host, ns_c_in, ns_t_mx, nsbuf, sizeof(nsbuf));
 if (l >= 0) {
           ns_initparse(nsbuf, l, &msg);
           l = ns_msg_count(msg, ns_s_an);
           for (i = 0; i < l; i++)
           {
                 ns_parserr(&msg, ns_s_an, i, &rr);
                 ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
                 memset(outTmp,'\0',N);
                 snprintf(outTmp, N, "\t%s\n", dispbuf);
                 printf("%s",outTmp);
                 dowyjscia = outTmp;
           }
 }

 // TXT
 l = res_query(host, ns_c_in, ns_t_txt, nsbuf, sizeof(nsbuf));
 if (l >= 0) {
     ns_initparse(nsbuf, l, &msg);
     l = ns_msg_count(msg, ns_s_an);
     for (i = 0; i < l; i++)
     {
           ns_parserr(&msg, ns_s_an, i, &rr);
           ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));

           memset(outTmp,'\0',N);
           snprintf(outTmp, N, "\t%s\n", dispbuf);
           printf("%s",outTmp);
           dowyjscia = outTmp;
     }
 }
 if(resultFile.length()!=0){
     FILE *f;
     f = fopen(resultFile.c_str(), "a");
     if (f == NULL)
     {
         printf("ERROR: Error opening file to output!\n");
         exit(1);
     }
     fprintf(f, "%s",dowyjscia.c_str());
     fclose(f);
 }


 return 0;
}


void *thread(void *arg) {

 char *ret;
 int argi;

 if(atype!=3){
     char line[BUFFSIZE_HOST], ch;
     int index = 0, skip=0;
     const int wylicz=(int)((long)arg*podzielone);
     const int wyliczUp=(int)(((long)arg*podzielone)+podzielone);
    
     char newhostname[BUFFSIZE_HOST+1];
     memset(newhostname,'\0',sizeof(newhostname));

     FILE *fp = fopen ( dictionary, "r");
     if(!fp){
         printf("\nERROR: Can not open dictionary file :( \n\n");
         pthread_exit(ret);
     }

     while ( (int)(ch = getc ( fp )) != EOF ) {
         if(wyliczUp<skip) return 0;
         if ( ch != '\n' && index<(BUFFSIZE_HOST-1)){
             line[index++] = ch;
         }else {
             line[index] = '\0';
             index = 0;

             if((skip++)>=wylicz){
                 snprintf(newhostname, BUFFSIZE_HOST, "%s.%s", line, hostname);
                 if(atype==1) checkArecord(newhostname);
                 else if(atype==2) takeOverCname(newhostname);
                 else generalCheck(newhostname);
             }
         }
      }
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
  printf(" -a      - Only find subdomains \n\n");
  printf(" -c      - Search CNAME to takeover \n\n");
  printf(" -x      - Search A,CNAME and bypass local resolver (direct DNS calls) \n\n");
  printf(" -r      - Verbose mode \n\n");
  printf(" example: %s -f dictionaries/common.txt -n servers/yandex.conf -o ./results/ -d domain.com -t 4\n\n",prog);
}

int main( int argc , char *argv[])
{
 int opt, idx;
 int chl=0, lines=0, nslines=0;
 int huy=0, index=0, outputsave=0;

 char chns;
 char dnsip[16];

 memset(hostname,'\0',BUFFSIZE_HOST);
 memset(dictionary,'\0',BUFFSIZE_HOST);
 memset(nsfile,'\0',BUFFSIZE_HOST);

 printf("\n==========================================\n hackDNS 0.1 - Fast DNS recon for hackers \n==========================================\n\n");

 while((opt = getopt(argc, argv, "d:n:f:o:t:acxrh")) != -1) {
     switch(opt){
     case 'd' :
         snprintf(hostname,BUFFSIZE_HOST,"%s",optarg);
         break;
     case 'n' :
         snprintf(nsfile,BUFFSIZE_HOST,"%s",optarg);
         break;
     case 'f' :
         snprintf(dictionary,BUFFSIZE_HOST,"%s",optarg);
         break;
     case 'o' :
         outputsave=1;
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
     case 'r' :
         debugMode=1;
         break;
     case 'h' :
         help(argv[0]);
         return 0;
         break;
     }
 }

 if(!*hostname){
     help(argv[0]);
     printf("ERROR: Hostname not defined.\n\n");
     return -1;
 }

 if(outputsave==1){
    resultFile += hostname;
    resultFile += ".";
    resultFile += to_string((int)time(NULL));
    resultFile += ".txt";
 }
 if(!*dictionary){
     snprintf(dictionary,BUFFSIZE_HOST,"./dictionary/common.txt");
 }

 FILE *fline = fopen(dictionary,"r");
 if(!fline){
     printf("\nERROR: Wrong path to dictionary file\n\n");
     return -1;
 }

 lines++;
 while ((int)(chl = fgetc(fline)) != EOF)
 {
     if (chl == '\n') lines++;
 }

 fclose(fline);
 podzielone=lines/threats;

 FILE *fns = fopen(nsfile,"r");
 if(!fns){
     printf("\nERROR: Wrong path to DNS server list (%s)\n\n",nsfile);
     return -1;
 }

 index=0;
 while ((chl = fgetc(fns)) != EOF)
 {
     if (chl == '\n'){ if(index>0) nslines++; index=0; continue; };
     index++;
 }
 index=0;
  
 if(atype==3){
     rewind(fns);
     int huy;
     if(MAX_DNS_SERVERS<nslines) nslines=1024;
     for(huy=0;huy<nslines;huy++){

       memset(dnsip,'\0',16);

       while ((int)(chns=getc ( fns )) != EOF) {
            if ( chns != '\n'){
                dnsip[index++] = chns;
            }else {
                dnsip[index] = '\0';
                dnservers[huy]=(char*)malloc(strlen(dnsip)+1);
                memset(dnservers[huy],'\0',strlen(dnsip)+1);

                strncpy(dnservers[huy],dnsip,strlen(dnsip));
                index = 0;
                definedDnsServers++;
                break;
           }
       }
   }  
 } else {
     rewind(fns);

     res_init();

     if(MAXNS<nslines){
        nslines=MAXNS;
     }
     _res.nscount = nslines;

     for(huy=0;huy<nslines;huy++){
         memset(dnsip,'\0',16);

         while ((int)(chns=getc ( fns )) != EOF) {
              if ( chns != '\n'){
                  dnsip[index++] = chns;
              }else {
                  dnsip[index] = '\0';
                  index = 0;
                  _res.nsaddr_list[huy].sin_family = AF_INET;
                  _res.nsaddr_list[huy].sin_addr.s_addr = inet_addr(dnsip);
                  _res.nsaddr_list[huy].sin_port = htons(53);
                  break;
             }
         }
     }
 }

 pthread_t thread_id[threats];

 int errorcode=0;
 for(idx=0; idx < threats; idx++)
 {
     if((errorcode=pthread_create( &thread_id[idx], NULL, thread, (void *)(uintptr_t)(idx)))!=0){
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
     FILE *f;
     f = fopen(resultFile.c_str(), "a");
     if (f == NULL)
     {
           printf("ERROR: Error opening file to output!\n");
           exit(1);
     }
     fprintf(f, "\n\n");
     fclose(f);
 }
 return 0;
}

