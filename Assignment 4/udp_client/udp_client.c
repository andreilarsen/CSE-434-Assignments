#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "../opcode_defines.h"

#define MAGIC_1			'A'
#define MAGIC_2			'L'

void init_message_header(unsigned char* buffer, unsigned char opcode, int messageLength, int messageID, int token)
{
	buffer[0] = MAGIC_1;
	buffer[1] = MAGIC_2;
	buffer[2] = opcode;
	buffer[3] = messageLength;
	buffer[4] = token >> 24;
	buffer[5] = token >> 16;
	buffer[6] = token >> 8;
	buffer[7] = token;
	buffer[8] = messageID >> 24;
	buffer[9] = messageID >> 16;
	buffer[10] = messageID >> 8;
	buffer[11] = messageID;
}

int main()
{
	int ret;
	int sockfd;
	struct sockaddr_in servaddr;
	unsigned char send_buffer[1024];
	unsigned char recv_buffer[1024];
	unsigned char user_input[1024];
	socklen_t len;
	int token = 0;

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
			m = strlen(user_input) - 5;
			if(m <= 0)
			{
				printf("The post message is empty. Post canceled. Please try again.\n");
				continue;
			}

			// Write the header
			init_message_header(send_buffer, OPCODE_POST, m, 0, token);

			// Write the data
			memcpy(send_buffer + 12, user_input + 5, m);
		}
		else if(strncmp(user_input, "retrieve#", 9) == 0)
		{
			m = strlen(user_input) - 10;	// Also subtract the newline
			if(m != 0)
			{
				printf("The retrieve command takes no parameters. Please try again.\n");
				continue;
			}

			// Write the header
			init_message_header(send_buffer, OPCODE_RETRIEVE, 0, 0, token);	// No data, set length to 0
		}
		else if(strncmp(user_input, "login#", 6) == 0)
		{
			m = strlen(user_input) - 6;
			char* ampersand = strchr(user_input + 6, '&');
			if(m <= 0 || ampersand == NULL)
			{
				printf("To login you must provide a username and password. Please try again.\n");
				continue;
			}

			// Write the header
			init_message_header(send_buffer, OPCODE_LOGIN, m - 1, 0, token);	// Don't want to copy the newline, subtract 1

			// Write the data
			memcpy(send_buffer + 12, user_input + 6, m - 1);	// Don't want to copy the newline, subtract 1
		}
		else if(strncmp(user_input, "subscribe#", 10) == 0)
		{
			m = strlen(user_input) - 10;

			if(m <= 0)
			{
				printf("To subscribe you must specify the target client. Please try again.\n");
				continue;
			}

			// Write the header
			init_message_header(send_buffer, OPCODE_SUBSCRIBE, m - 1, 0, token);	// Don't want to copy the newline, subtract 1

			// Write the data
			memcpy(send_buffer + 12, user_input + 10, m - 1);	// Don't want to copy the newline, subtract 1
		}
		else if(strncmp(user_input, "unsubscribe#", 12) == 0)
		{
			m = strlen(user_input) - 12;

			if(m <= 0)
			{
				printf("To unsubscribe you must specify the target client. Please try again.\n");
				continue;
			}

			// Write the header
			init_message_header(send_buffer, OPCODE_UNSUBSCRIBE, m - 1, 0, token);	// Don't want to copy the newline, subtract 1

			// Write the data
			memcpy(send_buffer + 12, user_input + 12, m - 1);	// Don't want to copy the newline, subtract 1
		}
		else
		{
			printf("Unrecognized command (command can be post# or retrieve#. Please try again.\n");
			continue;
		}

		// The sendto() function sends the designated number of bytes in the
		// "send_buffer" to the desitnation address.
		// Send the send_buffer, writing data_length + header_length (m + 12) bytes
		ret = sendto(sockfd, send_buffer, m + 12, 0, (struct sockaddr*) &servaddr, len);
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
		
		if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2)
		{
			switch(recv_buffer[2])
			{
				case OPCODE_POST_ACK:
					printf("post_ack#successful\n");
					break;
				case OPCODE_RETRIEVE_ACK:
					printf("retrieve_ack#");
					for(int i = 0; i < recv_buffer[3]; i++)
					{
						printf("%c", recv_buffer[i + 12]);
					}
					break;
				case OPCODE_SUCCESSFUL_LOGIN_ACK:
					token = (recv_buffer[4] << 24) | (recv_buffer[5] << 16) | (recv_buffer[6] << 8) | recv_buffer[7];
					printf("login_ack#%d\n", token);
					break;
				case OPCODE_FAILED_LOGIN_ACK:
					printf("login_fail#\n");
					break;
				case OPCODE_MUST_LOGIN_FIRST:
					printf("The server says you're not logged in. Please login using login#username&password.\n");
					break;
				case OPCODE_SUCCESSFUL_SUBSCRIBE_ACK:
					printf("Successfully subscribed to the client!\n");
					break;
				case OPCODE_FAILED_SUBSCRIBE_ACK:
					printf("The server could not subscribe you to the client. Please try again.\n");
					break;
				case OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK:
					printf("Successfully unsubscribed from the client!\n");
					break;
				case OPCODE_FAILED_UNSUBSCRIBE_ACK:
					printf("The server could not unsubscribe you from the client. Please try again.\n");
					break;
				case OPCODE_FORWARD:
					printf("FORWARDED MESSAGE:\n");
					for(int i = 0; i < recv_buffer[3]; i++)
					{
						printf("%c", recv_buffer[i + 12]);
					}

					// Write the header
					init_message_header(send_buffer, OPCODE_FORWARD_ACK, 0, 0, token);	// Don't want to copy the newline, subtract 1

					// Send the forward ACK
					ret = sendto(sockfd, send_buffer, 12, 0, (struct sockaddr*) &servaddr, len);
					if(ret <= 0)
					{
						printf("sendto() error: %s.\n", strerror(errno));
						return -1;
					}
					break;
				default:
					printf("Received a message from the server, but it does not match the expected format.\n");
					for(int i = 0; i < 36; i++)
					{
						printf("%c\n", recv_buffer[i]);
					}
					break;
			}
		}
	}

	return 0;	// Never executes
}
