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
    int middle_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(middle_socket == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

    char recv_packet[500], datagram[500], recv_get[1000], *pseudogram;

	//zero out the packet buffer
	memset(recv_packet, 0, 500);
    memset(recv_get, 0, 1000);

    //middle address
    struct sockaddr_in middle_address;
    middle_address.sin_family = AF_INET;
    middle_address.sin_port = htons(12345);
    middle_address.sin_addr.s_addr = inet_addr("10.0.0.2");

    //bind sv addr to socket
    bind(middle_socket, (struct sockaddr*) &middle_address, sizeof(middle_address));

    //IP header
    struct iphdr *recv_iph = (struct iphdr *) recv_packet, *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *recv_tcph = (struct tcphdr *) (recv_packet + sizeof (struct iphdr)), *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct pseudo_header psh;

    if(recvfrom(middle_socket, recv_packet, 500, 0, NULL, NULL)>0){
 
        printf("Packet received. Length: %d\n", recv_iph->tot_len);

        //client address
        struct sockaddr_in client_address;
        client_address.sin_family = AF_INET;
        client_address.sin_port = recv_tcph->source;
        client_address.sin_addr.s_addr = recv_iph->saddr;

        //Fill in the IP Header
        iph->ihl = recv_iph->ihl;
        iph->version = recv_iph->version;
        iph->tos = recv_iph->tos;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
        iph->id = 0;	//Id of this packet
        iph->frag_off = recv_iph->frag_off;
        iph->ttl = 64;
        iph->protocol = recv_iph->protocol;
        iph->check = 0;		//Set to 0 before calculating checksum
        iph->saddr = recv_iph->daddr;	//Spoof the source ip address
        iph->daddr = recv_iph->saddr;

        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        //TCP Header
        tcph->source = recv_tcph->dest;
        tcph->dest = recv_tcph->source;
        tcph->seq = 0;
        tcph->ack_seq = recv_tcph->seq + htonl(1);
        tcph->doff = 5;	//tcp header size
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh=0;
        tcph->ack=1;
        tcph->urg=0;
        tcph->window = htons (5840);	/* maximum allowed window size */
        tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;

        //Now the TCP checksum
        psh.source_address = middle_address.sin_addr.s_addr;
        psh.dest_address = recv_iph->saddr;
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
        
        if (setsockopt (middle_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }

        //Send the packet
        if (sendto (middle_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &client_address, sizeof (client_address)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf ("Packet Sent. Length : %d. Ack: %d" , iph->tot_len, tcph->ack_seq);
        }

        free(pseudogram);
    }
    if(recvfrom(middle_socket, recv_packet, 500, 0, NULL, NULL)>0){
        if(recv_tcph->ack == 1 && recv_tcph->ack_seq == (tcph->seq + htonl(1))){
            recvfrom(middle_socket, recv_get, 4096, 0, NULL, NULL);

            int midout_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if(midout_socket == -1)
            {
                //socket creation failed, may be because of non-root privileges
                perror("Failed to create socket");
                exit(1);
            }
            //midout address
            struct sockaddr_in midout_address;
            midout_address.sin_family = AF_INET;
            midout_address.sin_port = htons (12346);
            midout_address.sin_addr.s_addr = inet_addr ("10.0.0.2");

            //bind sv addr to socket
            bind(midout_socket, (struct sockaddr*) &midout_address, sizeof(midout_address));

            //server address
            struct sockaddr_in server_address;
            server_address.sin_family = AF_INET;
            server_address.sin_port = htons(25000);
            server_address.sin_addr.s_addr = inet_addr("10.0.0.3");

            //Fill in the IP Header
            iph->id += htonl(1);
            iph->check = 0;		//Set to 0 before calculating checksum
            iph->saddr = midout_address.sin_addr.s_addr;	//Spoof the source ip address
            iph->daddr = server_address.sin_addr.s_addr;
            //Ip checksum
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);

            //TCP Header
            tcph->source = htons (12346);
            tcph->dest = server_address.sin_port;
            tcph->seq = 0;
            tcph->ack_seq = 0;
            tcph->syn=1;
            tcph->ack=0;
            tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header

            //Now the TCP checksum
            psh.source_address = midout_address.sin_addr.s_addr;
            psh.dest_address = server_address.sin_addr.s_addr;
            psh.placeholder = 0;

            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
            pseudogram = malloc(psize);
            
            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
            
            tcph->check = csum( (unsigned short*) pseudogram , psize);

            //IP_HDRINCL to tell the kernel that headers are included in the packet
            int one = 1;
            const int *val = &one;
            
            if (setsockopt (midout_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
            {
                perror("Error setting IP_HDRINCL");
                exit(0);
            }

            //Send the packet
            if (sendto (midout_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
            {
                perror("sendto failed");
            }
            //Data send successfully
            else
            {
                printf ("Packet Send. Length : %d \n" , iph->tot_len);
            }
            //Send ACK
            if(recvfrom(midout_socket, recv_packet, 500, 0, NULL, NULL)>0){

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
                tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header

                memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
                tcph->check = csum( (unsigned short*) pseudogram , psize);

                //Send ACK
                if (sendto (midout_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
                {
                    perror("sendto failed");
                }
                //Data send successfully
                else
                {
                    printf ("Ack Sent. Length : %d." , iph->tot_len);
                }

                //Send GET
                if (sendto (midout_socket, recv_get, sizeof(recv_get) ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
                {
                    perror("send GET failed");
                }
                //Data send successfully
                else
                {
                    printf ("GET Sent. Length : %lu." ,sizeof(recv_get));
                }
            }

            free(pseudogram);
        }
    }
    

    return 0;
}