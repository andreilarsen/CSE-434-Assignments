#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAGIC_1			'A'
#define MAGIC_2			'L'
#define OPCODE_POST		0x01
#define OPCODE_POST_ACK		0x02
#define OPCODE_RETRIEVE		0x03
#define OPCODE_RETRIEVE_ACK	0x04

int main()
{
	int ret;
	int sockfd;
	struct sockaddr_in servaddr;
	char send_buffer[1024];
	char recv_buffer[1024];
	char user_input[1024];
	socklen_t len;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		printf("socket() error: %s.\n", strerror(errno));
		return -1;
	}

	// The "servaddr" is the server's address and port number
	// i.e., the destination address if the client needs to send something.
	// Note that this "servaddr" must match with the address in the
	// UDP server code.
	
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(32000);

	// TODO: You may declare a local address here.
	// You may also need to bind the socket to a local address and a port
	// number so that you can receive the echoed message from the socket.
	// You may also skip the binding process. In this case, every time you
	// call sendto(), the source port may be different.
	
	// Optionally, you can call connect() to bind the socket to a
	// destination address and port number. Since UDP is connectionless,
	// the connect() only set up parameters of the socket, no actual
	// datagram is sent. After that, you can call send() and recv() instead
	// of sendto() and recvfrom(). However, people usually do not do this
	// for a UDP based application layer protocol.
	
	while(1)
	{
		// The fgets() function reads a line from the keyboard (i.e., stdin)
		// to the "send_buffer".
		fgets(user_input, sizeof(user_input), stdin);

		// m is a variable that temporarily holds the length of the text
		// line typed by the user (not counting the "post#" or "retrieve#".
		int m = 0;
		len = sizeof(servaddr);

		// Compare the first five characters, check input format.
		// Note that strncmp() is case sensitive.
		if(strncmp(user_input, "post#", 5) == 0)
		{
			// Now we know it is a post message that should be sent.
			// Extract the input text line length, and copy the line to
			// the payload part of the message in the send_buffer. Note 
			// that the first four bytes are the header, so when we
			// copy the input line of text to the destination memory
			// buffer, i.e., the send_buffer + 4, there is an offset of
			// four bytes after the memory buffer that holds the whole
			// message. 

			// Note that in C and C++, array and pointer are interchangeable
			m = strlen(user_input) - 5;
			if(m <= 0)
			{
				printf("The post message is empty. Post canceled. Please try again.\n");
				continue;
			}
			memcpy(send_buffer + 4, user_input + 5, m);

			send_buffer[0] = MAGIC_1;
			send_buffer[1] = MAGIC_2;
			send_buffer[2] = OPCODE_POST;
			send_buffer[3] = m;
		}
		else if(strncmp(user_input, "retrieve#", 9) == 0)
		{
			m = strlen(user_input) - 10;	// Also subtract the newline
			if(m != 0)
			{
				printf("The retrieve command takes no parameters. Please try again.\n");
				continue;
			}
			send_buffer[0] = MAGIC_1;
			send_buffer[1] = MAGIC_2;
			send_buffer[2] = OPCODE_RETRIEVE;
			send_buffer[3] = m;
		}
		else
		{
			printf("Unrecognized command (command can be post# or retrieve#. Please try again.\n");
			continue;
		}

		// TODO: Check the user input format.
		// The sendto() function sends the designated number of bytes in the
		// "send_buffer" to the desitnation address.
		ret = sendto(sockfd, send_buffer, m + 4, 0, (struct sockaddr*) &servaddr, len);
		if(ret <= 0)
		{
			printf("sendto() error: %s.\n", strerror(errno));
			return -1;
		}

		ret = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*) &servaddr, &len);
		if(ret <= 0)
		{
			printf("recvfrom() error: %s.\n", strerror(errno));
			return -1;
		}
		
		if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2 && recv_buffer[2] == OPCODE_POST_ACK)
		{
			printf("post_ack#successful\n");
		}
		else if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2 && recv_buffer[2] == OPCODE_RETRIEVE_ACK)
		{
			printf("retrieve_ack#");
			for(int i = 0; i < recv_buffer[3]; i++)
			{
				printf("%c", recv_buffer[i + 4]);
			}
		}
		else
		{
			printf("Received a message from the server, but it does not match the expected format.\n");
			return -1;
		}
	}

	return 0;	// Never executes
}
