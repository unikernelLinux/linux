// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define BACKLOG 512
#define MAX_EVENTS 128
#define MAX_MESSAGE_LEN 2048

void error(char *msg);
extern long syscall(long number, ...);

int main(void)
{
	// some variables we need
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_len = sizeof(client_addr);
	int bytes_received;
	char buffer[MAX_MESSAGE_LEN];
	int on;
	int result;
	int sock_listen_fd, newsockfd;

	// setup socket
	sock_listen_fd = syscall(41, AF_INET, SOCK_STREAM, 0);
	if (sock_listen_fd < 0)
		error("Error creating socket..\n");

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = 45845; //htons(portno);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	// set TCP NODELAY
	on = 1;
	result = syscall(54, sock_listen_fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (result < 0)
		error("Can't set TCP_NODELAY to on");

	// bind socket and listen for connections
	if (syscall(49, sock_listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		error("Error binding socket..\n");

	if (syscall(50, sock_listen_fd, BACKLOG) < 0)
		error("Error listening..\n");

	struct epoll_event ev, events[MAX_EVENTS];
	int new_events, sock_conn_fd, epollfd;

	epollfd = syscall(213, MAX_EVENTS);
	if (epollfd < 0)
		error("Error creating epoll..\n");

	ev.events = EPOLLIN;
	ev.data.fd = sock_listen_fd;

	if (syscall(233, epollfd, EPOLL_CTL_ADD, sock_listen_fd, &ev) == -1)
		error("Error adding new listeding socket to epoll..\n");

	while (1) {
		new_events = syscall(232, epollfd, events, MAX_EVENTS, -1);

		if (new_events == -1)
			error("Error in epoll_wait..\n");

		for (int i = 0; i < new_events; ++i) {
			if (events[i].data.fd == sock_listen_fd) {
				sock_conn_fd = syscall(288, sock_listen_fd,
						(struct sockaddr *)&client_addr,
						&client_len, SOCK_NONBLOCK);
				if (sock_conn_fd == -1)
					error("Error accepting new connection..\n");

				ev.events = EPOLLIN | EPOLLET;
				ev.data.fd = sock_conn_fd;
				if (syscall(233, epollfd, EPOLL_CTL_ADD, sock_conn_fd, &ev) == -1)
					error("Error adding new event to epoll..\n");
			} else {
				newsockfd = events[i].data.fd;
				bytes_received = syscall(45, newsockfd, buffer, MAX_MESSAGE_LEN,
						0, NULL, NULL);
				if (bytes_received <= 0) {
					syscall(233, epollfd, EPOLL_CTL_DEL, newsockfd, NULL);
					syscall(48, newsockfd, SHUT_RDWR);
				} else {
					syscall(44, newsockfd, buffer, bytes_received, 0, NULL, 0);
				}
			}
		}
	}
}

void error(char *msg)
{
	syscall(1, 1, msg, 15);
	syscall(60, 1);
}
