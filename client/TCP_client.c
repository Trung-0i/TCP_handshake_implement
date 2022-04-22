#include <stdio.h>	//for printf
#include <stdlib.h>
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <sys/types.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/in.h>
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
// #include <unistd.h> // sleep()

/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

int main(){

    char datagram[500], source_ip[32], recv_packet[500], *pseudogram;
	//zero out the packet buffer
	memset (datagram, 0, 500);

	strcpy(source_ip, "10.0.0.2");

    int client_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(client_socket == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}
	//client address
	struct sockaddr_in client_address;
	client_address.sin_family = AF_INET;
	client_address.sin_port = htons (9000);
	client_address.sin_addr.s_addr = inet_addr ( source_ip );

	//bind sv addr to socket
	bind(client_socket, (struct sockaddr*) &client_address, sizeof(client_address));

    //server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(25000);
    server_address.sin_addr.s_addr = inet_addr("10.0.0.1");

    //IP header
	struct iphdr *iph = (struct iphdr *) datagram, *recv_iph = (struct iphdr *) recv_packet;
    //TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr)), *recv_tcph = (struct tcphdr *) (recv_packet + sizeof (struct iphdr));
	struct pseudo_header psh;

    //Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = server_address.sin_addr.s_addr;
    //Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    //TCP Header
	tcph->source = htons (9000);
	tcph->dest = server_address.sin_port;
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

    //Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = server_address.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
	
	tcph->check = csum( (unsigned short*) pseudogram , psize);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (client_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    //Send the packet
    if (sendto (client_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
    {
        perror("sendto failed");
    }
    //Data send successfully
    else
    {
        printf ("Packet Send. Length : %d \n" , iph->tot_len);
    }

	while(1) {
        if(recvfrom(client_socket, recv_packet, 500, 0, NULL, NULL)>0){

            printf("Packet received. Length: %d\n", recv_iph->tot_len);

            //Fill in the IP Header
            iph->id = recv_iph->id +htons(1);	//Id of this packet
            iph->check = 0;		//Set to 0 before calculating checksum

            //Ip checksum
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);

            //TCP Header
            tcph->seq= htonl(1);
            tcph->ack_seq = recv_tcph->seq + htonl(1);
            tcph->syn=0;
            tcph->ack=1;
			tcph->window = htons (42340);
            tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header

			memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
			tcph->check = csum( (unsigned short*) pseudogram , psize);

            //Send the packet
            if (sendto (client_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
            {
                perror("sendto failed");
            }
            //Data send successfully
            else
            {
                printf ("Packet Sent. Length : %d. Seq: %d, Ack: %d" , iph->tot_len, tcph->seq, tcph->ack_seq);
                break;
            }
        }
    }

    return 0;
}