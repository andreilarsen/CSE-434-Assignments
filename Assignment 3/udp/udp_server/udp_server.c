#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define MAGIC_1			'A'
#define MAGIC_2			'L'
#define OPCODE_POST		0x01
#define OPCODE_POST_ACK		0x02
#define OPCODE_RETRIEVE		0x03
#define OPCODE_RETRIEVE_ACK	0x04

void get_time_stamp(char* buffer)
{
	// Assume buffer has allocated enough data
	time_t raw_time;
	time(&raw_time);
	struct tm* time = localtime(&raw_time);
	snprintf(buffer, 20, "%02d/%02d/%04d %02d:%02d:%02d", time->tm_mon + 1, time->tm_mday, time->tm_year + 1900, time->tm_hour, time->tm_min, time->tm_sec);
}

int main()
{
	int ret;
	int sockfd;
	struct sockaddr_in servaddr, cliaddr;
	char recv_buffer[1024];
	char send_buffer[1024];
	int recv_len;
	socklen_t len;

	char recent_msg[201];

	FILE* log_file = fopen("udp_server.log", "w");

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("socket() error: %s.\n", strerror(errno));
		return -1;
	}

	// The servaddr is the address and port number that the server will 
	// keep receiving from.
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(32000);
	
	bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	
	while (1)
	{
		len = sizeof(cliaddr);
		recv_len = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *) &cliaddr, &len);
		
		if (recv_len <= 0)
		{
			printf("recvfrom() error: %s.\n", strerror(errno));
			return -1;
		}

		if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2 && recv_buffer[2] == OPCODE_POST)
		{
			memset(recent_msg, 0, sizeof(recent_msg));
			memcpy(recent_msg, recv_buffer + 4, recv_buffer[3]);

			send_buffer[0] = MAGIC_1;
			send_buffer[1] = MAGIC_2;
			send_buffer[2] = OPCODE_POST_ACK;
			send_buffer[3] = 0;
			
			char time_buffer[20];
			char port_buffer[3];
			get_time_stamp(time_buffer);
			snprintf(port_buffer, 3, "%d", cliaddr.sin_port);
			fputs("<", log_file);
			fputs(time_buffer, log_file);
			fputs("> [", log_file);
			fputs(inet_ntoa(cliaddr.sin_addr), log_file);
			fputs(": ", log_file);
			fputs(port_buffer, log_file);
			fputs("] post#", log_file);
			fputs(recent_msg, log_file);
			fflush(log_file);

			ret = sendto(sockfd, send_buffer, 4, 0, (struct sockaddr*) &cliaddr, len);
			if(ret <= 0)
			{
				printf("sendto() error: %s.\n", strerror(errno));
				return -1;
			}
		}
		else if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2 && recv_buffer[2] == OPCODE_RETRIEVE)
		{
			memset(send_buffer, 0, sizeof(send_buffer));
			memcpy(send_buffer + 4, recent_msg, strlen(recent_msg));

			send_buffer[0] = MAGIC_1;
			send_buffer[1] = MAGIC_2;
			send_buffer[2] = OPCODE_RETRIEVE_ACK;
			send_buffer[3] = strlen(recent_msg);

			char time_buffer[20];
			char port_buffer[3];
			get_time_stamp(time_buffer);
			snprintf(port_buffer, 3, "%d", cliaddr.sin_port);
			fputs("<", log_file);
			fputs(time_buffer, log_file);
			fputs("> [", log_file);
			fputs(inet_ntoa(cliaddr.sin_addr), log_file);
			fputs(": ", log_file);
			fputs(port_buffer, log_file);			
			fputs("] retrieve#\n", log_file);
			fflush(log_file);

			ret = sendto(sockfd, send_buffer, strlen(send_buffer), 0, (struct sockaddr*) &cliaddr, len);
			if(ret <= 0)
			{
				printf("sendto() error: %s.\n", strerror(errno));
				return -1;
			}
		}
		else
		{
			printf("A message was received, but it does not match the expected format.\n");
			continue;
		}
		
		
	}

	return 0;	// This should never execute
}
