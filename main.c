/*
hackDNS 0.2 - DNS brute force

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
#include <regex>

using namespace std;

///////////////////////////////////////////////////////////////////////////
int researchSpf(char *outTmp, unsigned int level);
///////////////////////////////////////////////////////////////////////////

#define N 4096
#define DNS_QUERY_SIZE 2048
#define PROTO_DNS_QTYPE_A 0x0001
#define PROTO_DNS_QTYPE_PTR 0x000c
#define PROTO_DNS_QTYPE_MX 0x000f
#define PROTO_DNS_QTYPE_TXT 0x0010
#define PROTO_DNS_QTYPE_AAAA 0x001c
#define PROTO_DNS_QTYPE_CNAME 0x0005
#define PROTO_DNS_QTYPE_ANY 0x00ff
#define MAX_SPF_LEVEL_RECURSION 10

static std::vector<std::string> qTypes;

#define PROTO_DNS_QCLASS_IP 0x0001
#define PROTO_DNS_QCLASS_ALL 0x00ff

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0x0
#endif

#define INET_ADDR(p1,p2,p3,p4) (htonl((p1 << 24) | (p2 << 16) | (p3 << 8) | (p4 << 0)))

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
# define SOCK_NONBLOCK O_NONBLOCK
#endif

std::map<int, std::string> outputDns;
std::mutex outputDns_mutex;
std::map<std::string, std::map<int,int>> scanResults;
std::mutex scanResults_mutex;
std::map<std::string, int> outputSpf;
std::mutex outputSpf_mutex;
std::map<std::string, int> scanSpfResults;
std::mutex scanSpfResults_mutex;

///////////////////////////////////////////////////////////////////////////

static uint32_t threats=1, atype=0, debugMode=0, lines=0, podzielone=0, resolveCount=1024, scanPorts=0, msTimeout=1000;
static uint32_t spfScan=0, spfPorts=0, checkHostByName=0, spfScanProcesses=50;
static uint32_t x, y, z, w;
static string hostname, nsfile, dictionary, resultFile;
static char *ipToSpf;
static std::vector<std::string> nsVec;
static std::vector<uint16_t> skanThisPorts = { 1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389 }; // default ports

typedef uint32_t ipv4_t;
typedef unsigned long int uintptr_tcust;

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

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

int strlen_buff(const char *str)
{
   if(str == NULL) return 0;
   int c = 0;

   while (*str++ != 0) c++;
   return c;
}
void zero_buff(void *buf, int len)
{
   char *zero = (char*)buf;
   while (len--) *zero++ = 0;
}
static void resolv_skip_name(uint8_t *wskReader, uint8_t *buffer, int *count)
{
   unsigned int jumped = 0, offset;

   *count = 1;
   while(*wskReader != 0)
   {
      if(*wskReader >= 192)
      {
          offset = (*wskReader) * 256 + *(wskReader+1) - 49152;
          wskReader = buffer + offset - 1;
          jumped = 1;
      }

      wskReader = wskReader + 1;
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
uint32_t rand_next(void){
   uint32_t t = x;
   t ^= t << 11;
   t ^= t >> 8;
   x = y; y = z; z = w;
   w ^= w >> 19;
   w ^= t;
   return w;
}
void resolv_domain_to_hostname(char *dstHostname, const char *srcDomain)
{
   int len = strlen_buff(srcDomain) + 1;
   char *lbl = dstHostname, *dstPosition = dstHostname + 1;
   uint8_t curr_len = 0;

   while (len-- > 0)
   {
       char c = *srcDomain++;

       if (c == '.' || c == 0){
           *lbl = curr_len;
           lbl = dstPosition++;
           curr_len = 0;
       } else {
           curr_len++;
           *dstPosition++ = c;
       }
   }
   *dstPosition = 0;
}
static bool port_is_open(string ip, uint16_t port){
   short int sock = -1;
   int so_error, rval, tries=0;
   struct timeval tv;
   struct sockaddr_in sa;
   fd_set fdset;

   strncpy((char*)&sa , "\0" , sizeof sa);
   sa.sin_family = AF_INET;
   sa.sin_port = htons(port);
   if(inet_pton(AF_INET, ip.c_str(), &sa.sin_addr)<=0){
       if(debugMode) cout << "inet failed for " << ip << endl;
       return -1;
   }

   sock = socket(AF_INET, SOCK_STREAM, 0);
   if(sock < 0){
       if(debugMode) cout << "sock failed port_is_open for " << ip << ":" << port << endl;
       return false;
   }

   if(1000<=msTimeout){
       tv.tv_sec = msTimeout/1000;
       tv.tv_usec = (msTimeout-(tv.tv_sec*1000))*1000;
   } else {
       tv.tv_sec = 0;
       tv.tv_usec = 1000 * msTimeout;
   }

   fcntl(sock, F_SETFL,  fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

   rval = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
   if (rval == 0 || (rval == -1 && errno == EINPROGRESS)){
       FD_ZERO(&fdset);
       FD_SET(sock, &fdset);

       rval=select(sock + 1, NULL, &fdset, NULL, &tv);

       if (rval == 1){
           socklen_t len = sizeof so_error;
           getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

           if(sock != -1)
               close(sock);
           if (so_error == 0){
               return true;
           }else{
               if(debugMode) cout << "soerror failed " << so_error << " for " << ip << ":" << port << endl;
               return false;
           }
       }
   }
   if(sock != -1)
       close(sock);

   return false;
}

///DNS ENGINE/////////////////////////////////////////////////////////////////////
void createPacket(struct dnshdr *dnsh, char *query, char *qname, int *query_len, const char *newHost, uint16_t *dns_id, struct dns_question *dnst, int type){
          dnsh = (struct dnshdr *)query;
          qname = (char *)(dnsh + 1);
          resolv_domain_to_hostname(qname, newHost);
          dnst = (struct dns_question *)(qname + strlen_buff(qname) + 1);
          *query_len = sizeof (struct dnshdr) + strlen_buff(qname) + static_cast<int>(1) + sizeof (struct dns_question);

          *dns_id = rand_next() % 0xffff;
          dnsh->id = *dns_id;
          dnsh->opts = htons(1 << 8);
          dnsh->qdcount = htons(1);
          dnst->qtype = htons(type);
          dnst->qclass = htons(PROTO_DNS_QCLASS_IP);
}
int sendPacket(int *fd, char *query, int *query_len, unsigned int *selectedDns, fd_set *fdset, struct timeval timeo, int *nfds){
          if (send(*fd, query, *query_len, MSG_NOSIGNAL) == -1)
          {
              if(debugMode) cout << "[WARNING] Failed to send packet. Errno: " << errno << " (DNS: " << nsVec[*selectedDns].c_str() << ")" << endl;
              if (*fd != -1)
                  close(*fd);
                  (*selectedDns)++;
              return -1;
          }

          fcntl(*fd, F_SETFL, O_NONBLOCK | fcntl(*fd, F_GETFL, 0));
          FD_ZERO(fdset);
          FD_SET(*fd, fdset);

          timeo.tv_sec = 1;
          timeo.tv_usec = 0;
          *nfds = select(*fd + 1, fdset, NULL, NULL, &timeo);

          if (*nfds == -1)
          {
                if(debugMode) cout << "[WARNING] select() failed" << endl;
                if(*fd != -1)
                    close(*fd);
                (*selectedDns)++;
                return -1;
          }
          else if (nfds == 0)
          {
                if(debugMode) cout << "[WARNING] Couldn't resolve (DNS: " << nsVec[*selectedDns].c_str() << ")" << endl;
                if(*fd != -1)
                    close(*fd);
                (*selectedDns)++;
                return -1;
          }

          return 0;
}
int connectToDnsServer(int *fd, unsigned int *selectedDns, struct sockaddr_in addr, const char *dnsserv){

          zero_buff(&addr, sizeof (struct sockaddr_in));
          addr.sin_family = AF_INET;
          inet_aton(dnsserv, &addr.sin_addr);
          addr.sin_port = htons(53);

          if(*fd != -1) close(*fd);

          if ((*fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
          {
              (*selectedDns)++;
              return -1;
          }

          if (connect(*fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
          {
              if(*fd != -1)
                  close(*fd);
              (*selectedDns)++;
              return -1;
          }

         return 0;
}
int readPacket(int *fd, char *qname, unsigned int *selectedDns,  struct dns_question *dnst, struct dnshdr *dnsh, uint16_t *dns_id, const char *host, int type, std::string &dowyja, unsigned int levelSpf){
         u_char response[N];
         char dispbuf[N], debuf[N];
         unsigned char *name;
         int stop, i, l, o;
         uint16_t ancount;
         ns_msg msg;
         string ip;

         memset(response,'\0',N);

         int ret = recvfrom(*fd, response,  sizeof (response), MSG_NOSIGNAL, NULL, NULL);

         if (ret < (sizeof (struct dnshdr) + strlen_buff(qname) + 1 + sizeof (struct dns_question))){
            if(debugMode) cout << "[WARNING] recfrom failed. ret: " << ret << endl;
            if (*fd != -1)
                close(*fd);
            (*selectedDns)++;
            return -1;
         }

         dnsh = (struct dnshdr *) response;
         qname = (char *)(dnsh + 1);
         dnst = (struct dns_question *)(qname + strlen_buff(qname) + 1);
         name = (unsigned char *)(dnst + 1);

         if (dnsh->id != *dns_id){
            if(debugMode) cout << "[WARNING] Collision ID received. dns_id is not the same as was sent." << endl;
            if(*fd != -1)
                close(*fd);
            (*selectedDns)++;
            return -1;
         }

         if (dnsh->ancount == 0){
            return 1; // NOT FOUND
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
             dowyja += "\t";
             dowyja += dispbuf;
             dowyja += "\n";

             if(rr.type==PROTO_DNS_QTYPE_PTR){
                  return 0;
             }

             if(rr.type==PROTO_DNS_QTYPE_A){
                  if (r_data->_class == htons(PROTO_DNS_QCLASS_IP))
                  {
                        memset(debuf, '\0', sizeof debuf);
                        inet_ntop(AF_INET, ns_rr_rdata(rr), debuf, sizeof(debuf));
                        ip = debuf;

                        if ( scanPorts && scanResults.find(ip) == scanResults.end() ) {
                             for (auto it = skanThisPorts.begin(); it != skanThisPorts.end(); it++) {
                                  if (port_is_open(ip, *it)){
                                      cout << "\t>>> Port " << ip << ":" << *it << " is open" << endl;
                                      scanResults_mutex.lock();
                                      scanResults[ip].insert(pair<int,int>(*it, 1));
                                      scanResults_mutex.unlock();
                                  }
                             }
                             scanResults_mutex.lock();
                             scanResults[ip].insert(pair<int,int>(0, 0));;
                             scanResults_mutex.unlock();
                        }
                  }
             }

             // SPF VERIFICATOR
             if(spfScan && rr.type==PROTO_DNS_QTYPE_TXT){

                     if(levelSpf<=MAX_SPF_LEVEL_RECURSION){

                         try {
                               regex spfIsPresent( "v\\=spf" );
                               std::cmatch results;

                               cout << "\t" << dispbuf << endl;

                               if(std::regex_search(dispbuf, results, spfIsPresent)) {
                                   researchSpf(dispbuf, levelSpf);
                               }
                               continue;
                         }

                         catch (const std::regex_error& e) {
                               std::cout << "regex_error caught: " << e.what() << '\n';
                         }
                     }
                     continue;
             }
             cout << "\t" << dispbuf << endl;
         }
         return 0;
}

int researchSpf(char *outTmp, unsigned int level){

         if(level++ > MAX_SPF_LEVEL_RECURSION) {
             cout << "WARNING! Recursion limit reached. It may mean that your SPF syntax is incorrect and hackers may try spoof email from this domain. Check SPF syntax" << endl;
             return -1;
         }

         string spfCheckString=outTmp, tempo;
         std::string::const_iterator start = spfCheckString.begin();
         unsigned int selectedDns=0;
         uint16_t dns_id;
         fd_set fdset;
         string linex;
         char *query;
         query=(char*)malloc(DNS_QUERY_SIZE);

         char failed=0;
         char *qname=NULL;
         string dowyja;

         struct dnshdr *dnsh;
         struct sockaddr_in addr = {0};
         struct dns_question *dnst;
         struct timeval timeo;

         int query_len, fd = -1, i = 0, nfds, selectedDnsTmp=0, tries=0;

         regex exludedLoops( "(google.com|outlook.com).( |\t)" );
         match_results<std::string::const_iterator> ignoreThisLookups;
         if(regex_search(spfCheckString, ignoreThisLookups, exludedLoops)){
             return 2;
         };

         try {
             regex ipV4template( "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?:\\/\\d{1,2}| |$))");
             match_results<std::string::const_iterator> resultIps;
             while ( regex_search(start, spfCheckString.cend(), resultIps, ipV4template) )
             {
                 outputSpf_mutex.lock();
                 outputSpf[resultIps[1]]=1;
                 outputSpf_mutex.unlock();
                 start = resultIps[0].second ;
             }
         }

         catch (const std::regex_error& e) {
            std::cout << "regex_error caught: " << e.what() << e.code() << endl;
         }

         regex recursiveSearch( "(include|a)\\:([a-zA-Z0-9\\.\\-_]{1,254}\\.[a-zA-Z]{2,}) ");
         match_results<std::string::const_iterator> resultLookups;
         start = spfCheckString.begin();

         while ( regex_search(start, spfCheckString.cend(), resultLookups, recursiveSearch) )
         {
              tempo=resultLookups[2];

              if (outputSpf.count(tempo)){
                   outputSpf_mutex.lock();
                   outputSpf[tempo] += 1;
                   outputSpf_mutex.unlock();

                   if(level++ > MAX_SPF_LEVEL_RECURSION)
                   {
                       break;
                   }
              } else {
                   outputSpf_mutex.lock();
                   outputSpf[tempo]=1;
                   outputSpf_mutex.unlock();

                   start = resultLookups[0].second;

                   establishConnectionDNServerSpf:
                   if(selectedDns>=nsVec.size()){
                       selectedDnsTmp=selectedDns/nsVec.size();
                       selectedDns=selectedDns-(selectedDnsTmp*(nsVec.size()));
                   }

                   if( resolveCount <= tries++ ){
                       if(debugMode) cout << "[WARNING] Couldn't check the SPF " << tempo << " Limit reached" << endl;
                       failed=0; tries=1;
                   }

                   if(connectToDnsServer(&fd, &selectedDns, addr, nsVec[selectedDns].c_str()) == -1){
                        if(debugMode) cout << "[WARNING] Spf check failed during creating socket (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
                        tries=0;
                        goto establishConnectionDNServerSpf;
                   }

                   memset(query,'\0',DNS_QUERY_SIZE);
                   createPacket(dnsh, query, qname, &query_len, tempo.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_TXT);

                   if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                       failed=1; goto establishConnectionDNServerSpf;
                   };

                   if (FD_ISSET(fd, &fdset))
                   {
                       if(readPacket(&fd, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_TXT, dowyja, level)==-1){
                           failed=1; goto establishConnectionDNServerSpf;
                       };
                   } else {
                       if(debugMode) cout << "[WARNING] SPF network connection failed (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
                           selectedDns++; failed=1;
                           goto establishConnectionDNServerSpf;
                   }
                   tries=0;
              }
         }

         if(fd != -1)
           close(fd);
         free(query);

         return 0;
}

int startCore(int idxServDns)
{
  rand_init();

  unsigned int selectedDns=idxServDns, thNum=selectedDns;

  char query[DNS_QUERY_SIZE];
  char failed=0;
  char *qname=NULL;
  string dowyja;

  struct dnshdr *dnsh;
  struct sockaddr_in addr = {0};
  struct dns_question *dnst;
  struct timeval timeo;

  const int wylicz=(int)((long)selectedDns*podzielone), consthread=idxServDns;
  int wyliczUp=(int)(((long)selectedDns*podzielone)+podzielone);
  int ilin=0, query_len, fd = -1, i = 0, nfds, selectedDnsTmp, tries=0;
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
  if( resolveCount <= tries++ ) {
     if(debugMode)
         cout << "[WARNING] Couldn't check the " << linex << " Limit attemps reached" << endl;
     failed=0; ilin++; tries=1;
  }

  if(connectToDnsServer(&fd, &selectedDns, addr, nsVec[selectedDns].c_str()) == -1){
      if(debugMode) cout << "[WARNING] Failed during creating socket (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
      tries=0;
      goto establishConnectionDNServer;
  }

  if (mydict.is_open())
  {
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
              // AAAA TYPE
              if(atype==2){
                   memset(query,'\0',DNS_QUERY_SIZE);
                   createPacket(dnsh, query, qname, &query_len, linex.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_AAAA);
                   if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                       failed=1; goto establishConnectionDNServer;
                   };
                   if (FD_ISSET(fd, &fdset))
                   {
                       if(readPacket(&fd, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_AAAA, dowyja, 0)==-1){
                            failed=1; goto establishConnectionDNServer;
                       };
                   } else {
                       if(debugMode) cout << "[WARNING] Network connection failed (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
                       selectedDns++; failed=1;
                       goto establishConnectionDNServer;
                   }
                   tries=0; continue;
              }

              // A TYPE
              gotoarec:
              memset(query,'\0',DNS_QUERY_SIZE);
              createPacket(dnsh, query, qname, &query_len, linex.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_A);
              if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                    failed=1; goto establishConnectionDNServer;
               };
              if (FD_ISSET(fd, &fdset))
              {
                   if(readPacket(&fd, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_A, dowyja, 0)==-1){
                        failed=1; goto establishConnectionDNServer;
                   };
              } else {
                   if(debugMode) cout << "[WARNING] Network connection failed (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
                   selectedDns++; failed=1;
                   goto establishConnectionDNServer;
              }

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
                  if(readPacket(&fd, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_MX, dowyja, 0)==-1){
                        failed=2; goto establishConnectionDNServer;
                   };
              } else {
                   if(debugMode) cout << "[WARNING] Network connection failed (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
                   selectedDns++; failed=2;
                   goto establishConnectionDNServer;
              }

              // TXT TYPE
              gototxtrec:
              memset(query,'\0',DNS_QUERY_SIZE);
              createPacket(dnsh, query, qname, &query_len, linex.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_TXT);
              if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
                    failed=3; goto establishConnectionDNServer;
              };
              if (FD_ISSET(fd, &fdset))
              {
                  if(readPacket(&fd, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_TXT, dowyja, 0)==-1){
                        failed=3; goto establishConnectionDNServer;
                   };
              } else {
                   if(debugMode) cout << "[WARNING] Network connection failed (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
                   selectedDns++; failed=3;
                   goto establishConnectionDNServer;
              }
              tries=0;
           } else {
                 mydict.ignore(1024, mydict.widen('\n'));
           }
       }
   } else {
       if(debugMode) cout << "\nERROR: Can not open dictionary file :( \n\n" << endl;
   }
   mydict.close();
   outputDns_mutex.lock();
   outputDns[consthread] = dowyja;
   outputDns_mutex.unlock();
   return 0;
}


int convertIPtoHostname(const char *ip, std::string &outPutHost){

   outPutHost.clear();
   char reversed_ip[INET_ADDRSTRLEN+1];
   char *query;
   int query_len, fd = -1, i = 0, nfds, selectedDnsTmp, tries=0, level=0;
   struct dnshdr *dnsh;
   struct sockaddr_in addr = {0};
   struct dns_question *dnst;
   struct timeval timeo;
   unsigned int selectedDns=0;
   uint16_t dns_id;
   fd_set fdset;
   string linex;
   char failed=0;
   char *qname=NULL;
   string dowyja;

   memset(reversed_ip, '\0', INET_ADDRSTRLEN+1);

   in_addr_t addrev;
   inet_pton(AF_INET, ip, &addrev);
   addrev = ((addrev & 0xff000000) >> 24) | ((addrev & 0x00ff0000) >>  8) | ((addrev & 0x0000ff00) <<  8) | ((addrev & 0x000000ff) << 24);

   inet_ntop(AF_INET, &addrev, reversed_ip, sizeof(reversed_ip));

   string spfCheckString=reversed_ip;

   std::string::const_iterator start = spfCheckString.begin() ;

   query=(char*)malloc(DNS_QUERY_SIZE);

   timeo.tv_sec = 1;
   timeo.tv_usec = 0;

   spfCheckString += ".in-addr.arpa";

   establishConnectionDNServerHost:
   if(selectedDns>=nsVec.size()){
       selectedDnsTmp=selectedDns/nsVec.size();
       selectedDns=selectedDns-(selectedDnsTmp*(nsVec.size()));
   }

   if( resolveCount <= tries++ ){
       if(debugMode)
           cout << "[WARNING] Couldn't check the PTR " << spfCheckString << " Limit reached" << endl;
           failed=0; tries=1;
   }

   if(connectToDnsServer(&fd, &selectedDns, addr, nsVec[selectedDns].c_str()) == -1){
        if(debugMode) cout << "[WARNING] Spf check failed during creating socket (DNS: " << nsVec[selectedDns].c_str() << ")" << endl;
            tries=0;
            goto establishConnectionDNServerHost;
        }

        memset(query,'\0',DNS_QUERY_SIZE);
        createPacket(dnsh, query, qname, &query_len, spfCheckString.c_str(), &dns_id, dnst, PROTO_DNS_QTYPE_PTR);

        if(sendPacket(&fd, query, &query_len, &selectedDns, &fdset, timeo, &nfds)==-1){
            failed=1; goto establishConnectionDNServerHost;
        };

        if (FD_ISSET(fd, &fdset)){
            if(readPacket(&fd, qname, &selectedDns, dnst, dnsh, &dns_id, linex.c_str(), PROTO_DNS_QTYPE_PTR, dowyja, level)==-1){
               failed=1; goto establishConnectionDNServerHost;
            };
        } else {
            if(fd != -1)
               close(fd);

            if(debugMode) cout << "[WARNING] PTR network connection failed (DNS: " << nsVec[selectedDns].c_str() << ") for " << spfCheckString << endl;
               selectedDns++; failed=1;  fd = -1; FD_ZERO(&fdset);
         }
         tries=0;

        if(fd != -1)
               close(fd);
        free(query);

        if(dowyja.length()){
               outPutHost=dowyja;
               return 0;
         }
         else return 1;
}

const char *convertIptoName(const char *ip) {
   string outme;
   convertIPtoHostname(ip, outme);
   return outme.c_str();
}

void *dziecko(void *arg) {
   const int param=(int)((long)arg);
   startCore(param);
   return 0;
}

void *scanSpfMultiThread(void *arg)
{
   const int port=(int)((long)arg);

   if (port_is_open(ipToSpf, port)) {
       scanSpfResults_mutex.lock();
       scanSpfResults[ipToSpf]=port;
       scanSpfResults_mutex.unlock();
   }

   return 0;
}


void help(char *prog)
{
     cout << " Use:" << endl;
     cout << " -d host - Domain name" << endl;
     cout << " -f file - Dictionary file path" << endl;
     cout << " -n file - Path to resolv file where are DNS servers" << endl;
     cout << " -o dir  - Directory path" << endl;
     cout << " -t int  - Number of threads (Default 1)" << endl;
     cout << " -c int  - Number of resolves for a name before giving up (Default 1024)" << endl;
     cout << " -a      - Check A type records (Default A, CNAME, TXT, MX)" << endl;
     cout << " -b      - Check AAAA type records (Default A, CNAME, TXT, MX)" << endl;
     cout << " -s      - Scan ports of A records (EXPERIMENTAL)" << endl;
     cout << " -r      - Scan ports of SPF records (EXPERIMENTAL)" << endl;
     cout << " -e int  - Number of threads for SPF port scanning (Default 50)" << endl;
     cout << " -p      - Specific port to scan (e.g. 22,80,443)" << endl;
     cout << " -i      - Timeout for port scanning in milliseconds (Default 1000ms)" << endl;
     cout << " -m      - Audit SPF records" << endl;
     cout << " -g      - Check host by name enable" << endl;
     cout << " -v      - Verbose mode" << endl;
     cout << " -h      - Show help info\n" << endl;
     cout << " example: " << prog << " -f dictionaries/hackdns.txt -n servers/cloudflare.conf -o ./results/ -d domain.com -t 64\n" << endl;
}


int main( int argc , char *argv[])
{
     int opt, idx, errorcode=0;
     unsigned int tmpPort, countPortScans=0;

     string hotOutputGethost, tmpResultMatch, nsentry;
     uint32_t ipaddress, subnetmask, netMask, ip;
     struct in_addr x;
     char * pch;

     cout << "\n==========================================\n hackDNS 0.2 - Fast DNS recon for hackers \n==========================================\n" << endl;

     while((opt = getopt(argc, argv, "d:n:f:o:t:e:c:p:i:abmgsrvh")) != -1) {
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
                threats = atoi(optarg);
                break;
            case 'e' :
                spfScanProcesses = atoi(optarg);
                break;
            case 'c' :
                resolveCount = atoi(optarg);
                break;
            case 'a' :
                atype=1;
                break;
            case 'g' :
                checkHostByName = 1;
                break;
            case 'm' :
                spfScan= 1;
                break;
            case 'r' :
                spfScan = 1;
                spfPorts = 1;
                break;
            case 'b' :
                atype = 2;
                break;
            case 's' :
                scanPorts = 1;
                break;
            case 'p' :
                skanThisPorts.clear();
                pch = strtok (optarg,",");
                while (pch != NULL)
                {
                  tmpPort=atoi(pch);
                  pch = strtok (NULL, ",");
                  if(65535<tmpPort || ( skanThisPorts.size() !=0 && std::find(skanThisPorts.begin(), skanThisPorts.end(),tmpPort)!=skanThisPorts.end()))
                  {
                      continue;
                  }
                  skanThisPorts.push_back(tmpPort);
                }
                break;
            case 'i' :
                msTimeout=atoi(optarg);
                if(3600000<msTimeout || msTimeout<1) msTimeout=1000;
                break;
            case 'v' :
                debugMode = 1;
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
        resultFile += hostname + "." + to_string((int)time(NULL)) + ".txt";
     }

     if(!dictionary.length()){
        dictionary = "./dictionary/jhaddix.;xt";
     }

     ifstream mydict (dictionary);
     if(!mydict){ cout << "\nCRITICAL: Wrong path to dictionary file\n" << endl; return -1; }
     while(mydict.ignore(1024, mydict.widen('\n'))) lines++;
     mydict.close();

     podzielone=lines/threats;

     ifstream myns2 (nsfile);
     if(!myns2){ cout << "\nCRITICAL: Wrong path to resolver file\n" << endl; return -1; }
     while(getline (myns2,nsentry)){
           nsVec.push_back(nsentry.c_str());
     }
     myns2.close();

     pthread_t thread_id[threats];
     pthread_t thread_spf[spfScanProcesses];

     for(idx=0; idx < threats; idx++)
     {
         if((errorcode=pthread_create( &thread_id[idx], NULL, dziecko, (void *)(uintptr_tcust)(idx)))!=0){
            cout << "ERROR: Can't create thread " << idx << ". Scan will be incomplete. Use lower value or try optimize your OS. Error code: " << errorcode << endl;
            sleep(5);
            threats=idx;
            break;
        };
     };

     for(idx=0; idx < threats; idx++)
     {
            pthread_join( thread_id[idx], NULL);
     }

     std::ofstream outfile;
     if(resultFile.length()!=0){
            outfile.open(resultFile.c_str());
     }

     outputDns_mutex.lock();
     for (const auto &pair : outputDns){
            if(0<pair.second.length())
                  outfile << pair.second;
     }
     outputDns_mutex.unlock();

     if(scanPorts){
           if(outfile.is_open()) outfile << "\n=== PORT SCAN RESULT ==================================\n" << endl;
           cout << "\n=== PORT SCAN RESULT ==================================\n" << endl;

           scanResults_mutex.lock();
           for (const auto &pair : scanResults) {
                 cout << "===> Scanned " << pair.first <<  " (revdns " << convertIptoName(pair.first.c_str()) << ")\n";
                 if(outfile.is_open())  outfile << "===> Scanned " << pair.first <<  " (revdns " << convertIptoName(pair.first.c_str()) << ")\n";
                 for (const auto &pair2 : pair.second) {

                      if(pair2.second == 1){
                         if(outfile.is_open())  outfile << "Found open port: " << pair.first << ":" << pair2.first << endl;
                         cout << "Found open port: " << pair.first << ":" << pair2.first << endl;
                      }
                 }
           }
           scanResults_mutex.unlock();
     }

     if(checkHostByName || spfScan){
         if(outfile.is_open()) outfile << "\n\n=============== SPF RECORD AUDIT ===============\n\n";
         cout << "\n\n=============== SPF RECORD AUDIT ===============\n\n";
         outputSpf_mutex.lock();
     }

     if(!outputSpf.empty()){

         for (const auto &pair : outputSpf) {
             if(outfile.is_open()) outfile << pair.first << " ";
             cout << pair.first << " ";
             if(MAX_SPF_LEVEL_RECURSION<=pair.second){
               if(outfile.is_open()) outfile << "(POSSIBLE RECURSION) ";
               cout << "(POSSIBLE RECURSION)";
             }
             if(outfile.is_open()) outfile << endl;
             cout << endl;
         }

         if(checkHostByName || spfPorts)
         for (const auto &pair : outputSpf) {
             regex ipV4template( "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" ) ;
             match_results<std::string::const_iterator> resultIps;
             std::string start = pair.first;

             // IP check
             regex_search(start, resultIps, ipV4template);

             if(resultIps[1].length()){
                   tmpResultMatch=resultIps[1];

                   regex ipMask( "\\/(\\d{1,3})" ) ;
                   match_results<std::string::const_iterator> resultMask;
                   std::string mask = pair.first;

                   regex_search(mask, resultMask, ipMask);

                   if(resultMask[1].length()){
                       netMask = (0xFFFFFFFF << (32 - stoi(resultMask[1].str())) & 0xFFFFFFFF);
                       ipaddress = ntohl(inet_addr(tmpResultMatch.c_str()));
                       subnetmask = netMask;

                       for( uint32_t i = 0; i < (~subnetmask) || ( i==0 && (~subnetmask) == 0); i++ ){
                           ip = (ipaddress & subnetmask) | i;
                           x = { htonl(ip) };

                           if(checkHostByName){
                               if(convertIPtoHostname(inet_ntoa(x), hotOutputGethost)==0){
                                   if(outfile.is_open()) outfile << hotOutputGethost;
                                   cout << hotOutputGethost;
                               };
                           }

                           ipToSpf = inet_ntoa(x);

                           for (auto it = skanThisPorts.begin(); it != skanThisPorts.end(); it++) {
                               if(spfScanProcesses <= countPortScans) {
                                   for(idx=0; idx < countPortScans; idx++){
                                       pthread_join( thread_spf[idx], NULL);
                                   }

                                   countPortScans=0;
                               }
                               if((errorcode=pthread_create( &thread_spf[countPortScans++], NULL, scanSpfMultiThread, (void *)(uintptr_tcust)(*it)))!=0){
                                   cout << "ERROR: Can't create new thread. Code " << errorcode << endl;
                                   sleep(5);
                                   break;
                               };
                           }

                           for(idx=0; idx < countPortScans; idx++){
                               pthread_join( thread_spf[idx], NULL);
                               countPortScans=0;
                           }

                           scanSpfResults_mutex.lock();
                           for (const auto &pair : scanSpfResults){
                                   cout << ">>> Port " << pair.first << ":" << pair.second << " open." << endl;
                                   if(outfile.is_open()) outfile << ">>> Port " << pair.first << ":" << pair.second << " open." << endl;
                           }
                           scanSpfResults_mutex.unlock();
                           scanSpfResults.clear();
                       }
                   } else {
                       if(checkHostByName){
                           if(convertIPtoHostname(tmpResultMatch.c_str(), hotOutputGethost)==0){
                               cout << hotOutputGethost;
                           }
                       }
                   }
             }
         }
         outputSpf_mutex.unlock();
     } else if(checkHostByName){
         if(outfile.is_open()) outfile << "\n !!! NO SPF RECORD FOUND !!!\n\n";
         cout << "\n !!! NO SPF RECORD FOUND !!!\n\n";
     }

     if(resultFile.length()!=0){
         outfile.close();
     }

     return 0;
}

