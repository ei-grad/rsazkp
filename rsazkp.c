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

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"


BIO * out;
BIO * err;


int ExtendedEuclidianAlgorithm(BIGNUM * a, BIGNUM * b, BIGNUM * d, BIGNUM * x, BIGNUM * y){
    
    if (BN_is_zero(b)) {
        BN_copy(d, a);
        BN_one(x);
        BN_zero(y);
        return 0;
    }

    BN_CTX * ctx = BN_CTX_new();

    BIGNUM * a1 = BN_new();
    BIGNUM * b1 = BN_new();

    BIGNUM * x1 = BN_new();
    BIGNUM * x2 = BN_new();

    BIGNUM * y1 = BN_new();
    BIGNUM * y2 = BN_new();

    BIGNUM * q = BN_new();
    BIGNUM * r = BN_new();

    BIGNUM * tmp1 = BN_new();

    BN_copy(a1, a);
    BN_copy(b1, b);

    BN_one(x2);
    BN_zero(x1);
    BN_zero(y2);
    BN_one(y1);

    while (!BN_is_zero(b)) {
        
        // I

        BN_div(q, NULL, a, b, ctx); // q = floor(a / b)

        BN_mul(tmp1, q, b, ctx);
        BN_sub(r, a, tmp);          // r = a - q * b
        
        BN_mul(tmp1, q, x1, ctx);
        BN_sub(x, x2, tmp1);        // x = x2 - q * x1

        BN_mul(tmp1, q, y1, ctx);
        BN_sub(y, y2, tmp1);        // y = y2 - q * y1


        // II
        
        BN_copy(a, b);              // a <- b
        BN_copy(b, r);              // b <- r
        BN_copy(x2, x1);            // x2 <- x1
        BN_copy(x1, x);             // x1 <- x
        BN_copy(y2, y1);            // y2 <- y1
        BN_copy(y1, y);             // y1 <- y

    }

    // Result
    
    BN_copy(d, a);
    BN_copy(x, x2);
    BN_copy(y, y2);

    // Free

    BN_CTX_free(ctx);

    BN_free(a1);
    BN_free(b1);

    BN_free(x1);
    BN_free(x2);

    BN_free(y1);
    BN_free(y2);

    BN_free(q);
    BN_free(r);

    BN_free(tmp1);

    return 0;
}

int GetMultiplicativeInverse(BIGNUM * res, BIGNUM * a, BIGNUM * n) {
    
    int ret = 1;

    BIGNUM * d, * x, * y;

    d = BN_new();
    x = BN_new();
    y = BN_new();

    ExtendedEuclidianAlgorithm(a, n, d, x, y);

    if (BN_is_one(d)) {
        BN_copy(res, x);
        ret = 0;
    }

    BN_free(d);
    BN_free(x);
    BN_free(y);

    return ret;
}

struct Client {
    RSA * rsa;
    BIGNUM * k;
    BIGNUM * m;
    BIO * conn;
};



int Act1(Client &client) {

    BIGNUM * k = BN_new();
    BIGNUM * m = BN_new();
    
    BIO_write(bio_out, "Этап 1\n");

    do {
        BN_rand(k, (rsa->e.top - 1) * sizeof(BN_ULONG), -1, false);
        BIO_write(out, "Ищем обратный по умножению к числу ");
        BN_print(out, k);
        BIO_write(out, "\n");
    } while(GetMultiplicativeInverse(m, k, rsa->n));

    BIO_write("k = ");
    BN_print(out, k);
    BIO_write("\nm = ");
    BN_print(out, m);
    BIO_write(out, "\n");

    BIO_write(out, "Отправляем k и m серверу...");
    BN_print(client.conn, k);
    BN_print(client.conn, m);

    return 0;
}

int HandleClient(BIO * bio_client){
    int bytes;
    char tmpstr[1024];
    bytes = BIO_read(bio_client, tmpstr, 1024);
    tmpstr[bytes] = 0;
    printf("%s\n", tmpstr);
    BIO_puts(bio_client, "Hello, client!");
    BIO_free(bio_client);
    return 0;
}

int server(char ** argv) {
    int i;
    BIO * bio_listen = BIO_new_accept(*argv);
    argv++;
    BIO_set_bind_mode(bio_listen, BIO_BIND_REUSEADDR);
    /* First call to BIO_accept() sets up accept BIO */
    if(BIO_do_accept(bio_listen) <= 0) {
        fprintf(stderr, "Error setting up accept\n");
        return 1;
    }
    for(i=0;i<10;i++){
        /* Wait for incoming connection */
        if(BIO_do_accept(bio_listen) <= 0) {
            fprintf(stderr, "Error accepting connection\n");
            return 1;
        }
        fprintf(stderr, "Connection established!\n");
        BIO * bio_client;
        HandleClient(BIO_pop(bio_listen));
    }
    BIO_free(bio_listen);
    return 0;
}

int clientConnect(Client * client, char * addr) {
    char tmpstr[1024];
    int bytes;
    Client client;

    client->conn = BIO_new_connect(*argv);

    if (BIO_do_connect(Client->conn) <= 0) {
        BIO_write(err, "Error connecting to server!\n");
        return 1;
    }
    return 0;
}

int clientReadKey(Client * client, char * key) {
    FILE * f;
    if ((f = fopen(key, "r")) == NULL) {
        return 1;
    }
    
    client->rsa = RSA_new();
    if (client->rsa == NULL) {
        return 1;
    }

    PEM_read_RSAPrivateKey(f, &client->rsa, password_cb, NULL);

    return 0;
}

int clientFree(client) {
    BIO_free(client.conn);
    RSA_free(client.rsa);
    BN_free(client.k);
    BN_free(client.m);
    return 0;
}

int clientMain(char ** argv) {
    
    Client client;

    if(clientConnect(&client, argv[0])) {
        return 1;
    }

    if(clientReadKey(&client, argv[1])) {
        return 1;
    }

    Act1(client);
    
    clientFree(client);
    return 0;
}

#define using "using: rsazkp client|server <ip>:<port> <key>"

int main(int argc, char * argv[]) {

    int ret=1;

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    err = BIO_new_fp(stderr, BIO_NOCLOSE);

    SSL_load_error_strings();
    SSL_library_init();
    
    if (argc != 4) {
        fprintf(stderr, "%s\n", using);
    }
    argc--; argv++;
    if (strcmp("client", *argv) == 0) {
        argc--; argv++;
        ret = clientMain(argv);
    } else if (strcmp("server", *argv) == 0) {
        argc--; argv++;
        ret = serverMain(argv);
    } else {
        fprintf(stderr, "%s\n", using);
    }
    if (ret)
        ERR_print_errors_fp(stderr);
    return ret;
}

