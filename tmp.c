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

        //Send the packet
        if (sendto (midout_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
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