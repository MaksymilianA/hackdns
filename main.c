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

#define N 4096
#define BUFFSIZE_HOST 1024

static int threats=1;
static char hostname[BUFFSIZE_HOST+1];
static char nsfile[BUFFSIZE_HOST+1];
static char dictionary[BUFFSIZE_HOST+1];
static int podzielone;
static int atype=0;


int checkDomain3(char *host)
{
  if(atype){ 
    struct hostent *lh = gethostbyname(host);
    if (lh){
         printf("%s\n", host);
    }
    return 0;
  }
  u_char nsbuf[N];
  char dispbuf[N];
  ns_msg msg;
  ns_rr rr;
  int i, l;
    
  // A RECORD
  l = res_query(host, ns_c_in, ns_t_a, nsbuf, sizeof(nsbuf));
  if (l >= 0) {
      
      ns_initparse(nsbuf, l, &msg);
      l = ns_msg_count(msg, ns_s_an);

      for (i = 0; i < l; i++) {
            ns_parserr(&msg, ns_s_an, i, &rr);
            ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
            printf("\t%s \n", dispbuf);
      }
  }

  // CNAME
  l = res_query(host, ns_c_in, ns_t_ns, nsbuf, sizeof(nsbuf));
  if (l >= 0) {
      ns_initparse(nsbuf, l, &msg);
      l = ns_msg_count(msg, ns_s_an);
      return 0;
  }

  // MX RECORD
  l = res_query(host, ns_c_in, ns_t_mx, nsbuf, sizeof(nsbuf));
  if (l >= 0) {
            ns_initparse(nsbuf, l, &msg);
            l = ns_msg_count(msg, ns_s_an);
            for (i = 0; i < l; i++)
            {
              ns_parserr(&msg, ns_s_an, i, &rr);
              ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
              printf ("\t%s\n", dispbuf);
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
        printf("\t%s \n", dispbuf);
      }
  }

  return 0;
}


void *thread(void *arg) {

  char line[BUFFSIZE_HOST], ch;
  char *ret;
  int index = 0, skip=0;
  const int wylicz=podzielone+(int)arg;

  char newhostname[BUFFSIZE_HOST+1];
  memset(newhostname,'\0',sizeof(newhostname));

  FILE *fp = fopen ( dictionary, "r");
  if(!fp){
      printf("\nERROR: Can not open dictionary file :( \n\n");
      pthread_exit(ret);
  }

  while ( (ch = getc ( fp )) != EOF ) {
      if(wylicz<skip) return 0;
      if ( ch != '\n' && index<(BUFFSIZE_HOST-1)){
          line[index++] = ch;
      }else {
          line[index] = '\0';
          index = 0;

          if((skip++)>(int)arg){
              snprintf(newhostname, BUFFSIZE_HOST, "%s.%s", line, hostname);
              checkDomain3(newhostname);
          }
      }
//      ch = getc ( fp );
   }
   pthread_exit(ret);
}

void help(char *prog)
{
   printf(" Use: \n");
   printf(" -d host - Domain name\n");
   printf(" -f file - Dictionary file path\n");
   printf(" -n file - Path to resolv file where are DNS servers\n");
   printf(" -t int  - Number of threats. (Default 1)\n");
   printf(" -a      - Only find subdomains \n\n");
   printf(" example: %s -d domain.com -f dictionaries/common.txt -n servers/yandex.conf -t 4\n\n",prog);
}

int main( int argc , char *argv[])
{
  int opt, idx;
  int chl=0, lines=0, nslines=0;
  int huy=0, index=0;

  char chns;
  char dnsip[16];

  memset(hostname,'\0',BUFFSIZE_HOST);
  memset(dictionary,'\0',BUFFSIZE_HOST);
  memset(nsfile,'\0',BUFFSIZE_HOST);

  printf("\n==========================================\n fuckDNS 0.1 - Fast DNS recon for hackers \n==========================================\n\n");

  while((opt = getopt(argc, argv, "d:n:f:t:ah")) != -1) {
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
      case 't' :
          threats=atoi(optarg);
          break;
      case 'a' :
          atype=1;
          break;
      case 'h' :
          help(argv[0]);
          return 0;
          break;
      }
  }

  if(!*hostname){
      help(argv[0]);
      printf("ERROR: Hostname not defined.");
      return -1;
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
  while ((chl = fgetc(fline)) != EOF)
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
 
  nslines++;
  while ((chl = fgetc(fns)) != EOF)
  {
      if (chl == '\n') nslines++;
  }
  if(chl == '\n') nslines--;
  rewind(fns);
 
  res_init();

   if(MAXNS<nslines){
       nslines=MAXNS;
   }
  _res.nscount = nslines;

  for(huy=0;huy<nslines;huy++){
      memset(dnsip,'\0',16);
     
      while ((chns=getc ( fns )) != EOF) {
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

  pthread_t thread_id[threats];

  for(idx=0; idx < threats; idx++)
  {
      pthread_create( &thread_id[idx], NULL, thread, (void *)(uintptr_t)(idx*podzielone));
  }

  for(idx=0; idx < threats; idx++)
  {
      pthread_join( thread_id[idx], NULL);
  }

  return 0;
}

