/*
 * Copyright (c) 2009 Andrew S. Grigorev, Chelyabinsk State University
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
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "apps.h"
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#undef PROG
#define PROG client

int Connect(char * address, int port){
    int sock;
    struct sockaddr_in server;

    /* Create the TCP socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        fprintf(stderr, "Failed to create socket\n");
        exit(1);
    }
    
    /* Construct the server sockaddr_in structure */
    memset(&server, 0, sizeof(server));       /* Clear struct */
    server.sin_family = AF_INET;                  /* Internet/IP */
    server.sin_addr.s_addr = inet_addr(address);  /* IP address */
    server.sin_port = htons(port);                /* server port */
    
    /* Establish connection */
    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        fprintf(stderr, "Failed to connect\n");
        exit(1);
    }

    return sock;
}

int client(int argc, char * argv[]){
    int ret = 0;

    /*if (argc != 2) {
        fprintf(stderr, "USAGE: client <server_ip>\n");
        exit(1);
    }*/
    
    FILE * f;
    if ((f = fopen("private.pem", "r")) == NULL)
        goto err;
    PW_CB_DATA cb_data;
    RSA *rsa = RSA_new();
    if (!PEM_read_RSAPrivateKey(f, &rsa, (pem_password_cb *) password_callback, &cb_data))
        goto err;

    //int sock = Connect(argv[2]);

err:
    if (rsa) RSA_free(rsa);
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    apps_shutdown();
    OPENSSL_EXIT(ret);
    return 0;
}

