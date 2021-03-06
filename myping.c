// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
//
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()


// IPv4 header len without options

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.


int main (int count, char *strings[])
{
    if(count < 2)
    {
      printf("Please Enter the destination address!\n");
      exit(1);
    }
    //struct ip iphdr; // IPv4 header deleted, we build only ICMP headers.
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;
    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // First, IP header.
    //memcpy (packet, &iphdr, IP4_HDRLEN);<------ip

    // Next, ICMP header
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
#if defined _WIN32
    dest_in.sin_addr.s_addr = iphdr.ip_dst;
#else
    struct in_addr ip_dst;
    ip_dst.s_addr=0;
    //unsigned long ip_dst;
    if (inet_pton (AF_INET,strings[1],&ip_dst) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for destination-ip with error: %d", errno);
        return -1;
    }
    dest_in.sin_addr.s_addr = ip_dst.s_addr;
#endif


#if defined _WIN32
    WSADATA wsaData = { 0 };
	int iResult = 0;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}
#endif

    // Create raw socket 
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf (stderr, "socket() failed with error: %d"
#if defined _WIN32
                , WSAGetLastError()
#else
                , errno
#endif
        );
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    //Measure the time that took to do a "ping" and recive "pong".
    struct timeval start,end;
    gettimeofday(&start,NULL);

    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet,ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)
    {
        fprintf (stderr, "sendto() failed with error: %d"
#if defined _WIN32
                , WSAGetLastError()
#else
                , errno
#endif
        );
        return -1;
    }
    char receivedMessage[IP_MAXPACKET];
    struct sockaddr_in recv;
    socklen_t size=0;
    memset (&recv, 0, sizeof (struct sockaddr_in));
    if((recvfrom(sock,receivedMessage, IP_MAXPACKET,0,(struct sockaddr*)&recv,(&size))==-1)){
        fprintf (stderr, "receivefrom() failed with error: %d"
#if defined _WIN32
                , WSAGetLastError()
#else
                , errno
#endif
        );
        return -1;
    }
    gettimeofday(&end, NULL);
    long seconds = (end.tv_sec - start.tv_sec);
    long micros = (seconds)*1000000+end.tv_usec-start.tv_usec;
    double time_spent= seconds+((double)micros/1000000);
    long millis = time_spent*1000;
    printf("RTT time in milliseconds: %ld ms,RTT time in microseconds: %ld \n",millis,micros);




    // Close the raw socket descriptor.
#if defined _WIN32
    closesocket(sock);
  WSACleanup();
#else
    close(sock);
#endif

    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short * w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}


