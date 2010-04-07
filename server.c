/*
 * Copyright (c) 2009-2010 Andrew S. Grigorev, Chelyabinsk State University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

void Server_HandleClient(int sock){

    return;
}

int Server(){
    
    int server_socket;
    struct sockaddr_in server_sa;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        fprintf(stderr, "Failed to create socket\n");
        exit(1);
    }

    memset(&server_sa, 0, sizeof(server_sa));
    server_sa.sin_family = AF_INET;
    server_sa.sin_addr.s_addr = htonl(INADDR_ANY);
    server_sa.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *) &server_sa,
                            sizeof(server_sa)) < 0) {
        fprintf(stderr, "Failed to bind server socket\n");
    }

    if (listen(server_socket, 50) < 0) {
        fprintf(stderr, "Failed to listen on server socket\n");
    }

    /* Run until cancelled */
    while (1) {
        int client_socket;
        struct sockaddr_in client_sa;
        unsigned int client_sa_len = sizeof(client_sa);
        /* Wait for client connection */
        if ((client_socket =
              accept(server_socket, (struct sockaddr *) &client_sa,
              &client_sa_len)) < 0) {
                fprintf(stderr, "Failed to accept client connection\n");
            }
        fprintf(stdout, "Client connected: %s\n",
            inet_ntoa(client_sa.sin_addr));
        Server_HandleClient(client_socket);
    }

    return 0;
}

