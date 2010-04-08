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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ui.h>

static UI_METHOD *ui_method = NULL;
static BIO * bio_out;
static BIO * bio_err;

#define PW_MIN_LENGTH 4
typedef struct pw_cb_data
{
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

void destroy_ui_method(void) {
	if(ui_method) {
		UI_destroy_method(ui_method);
		ui_method = NULL;
	}
}

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp) {
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data) {
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password) {
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	ui = UI_new_method(ui_method);
	if (ui) {
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase",
			prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
				PW_MIN_LENGTH,BUFSIZ-1);
		if (ok >= 0 && verify)
			{
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
				PW_MIN_LENGTH,BUFSIZ-1, buf);
			}
		if (ok >= 0)
			do {
				ok = UI_process(ui);
			} while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff) {
			OPENSSL_cleanse(buff,(unsigned int)bufsiz);
			OPENSSL_free(buff);
		}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1) {
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors(bio_err);
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		if (ok == -2) {
			BIO_printf(bio_err,"aborted!\n");
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		UI_free(ui);
		OPENSSL_free(prompt);
	}
	return res;
}

int ExtendedEuclidianAlgorithm(BIGNUM * a, BIGNUM * b, BIGNUM * d, BIGNUM * x, BIGNUM * y) {
    
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

    BIGNUM * tmp = BN_new();

    BN_copy(a1, a);
    BN_copy(b1, b);

    BN_one(x2);
    BN_zero(x1);
    BN_zero(y2);
    BN_one(y1);

    while (!BN_is_zero(b1)) {
        
        // I

        BN_div(q, NULL, a1, b1, ctx); // q = floor(a1 / b1)

        BN_mul(tmp, q, b1, ctx);
        BN_sub(r, a1, tmp);          // r = a1 - q * b1
        
        BN_mul(tmp, q, x1, ctx);
        BN_sub(x, x2, tmp);        // x = x2 - q * x1

        BN_mul(tmp, q, y1, ctx);
        BN_sub(y, y2, tmp);        // y = y2 - q * y1


        // II
        
        BN_copy(a1, b1);              // a1 <- b1
        BN_copy(b1, r);              // b1 <- r
        BN_copy(x2, x1);            // x2 <- x1
        BN_copy(x1, x);             // x1 <- x
        BN_copy(y2, y1);            // y2 <- y1
        BN_copy(y1, y);             // y1 <- y

    }

    // Result
    
    BN_copy(d, a1);
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

    BN_free(tmp);

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

typedef struct client {
    RSA * rsa;
    BIGNUM * k;
    BIGNUM * m;
    BIO * conn;
} Client;

int clientAct1(Client * client) {
    
    char * tmpstr;

    BIGNUM * k = BN_new();
    BIGNUM * m = BN_new();
    
    BIO_puts(bio_out, "Этап 1\n");

    do {
        BN_rand_range(k, client->rsa->n);
        tmpstr = BN_bn2dec(k);
        printf("Ищем обратный по умножению к числу %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    } while(GetMultiplicativeInverse(m, k, client->rsa->n));

    client->k = k;
    client->m = m;
    
    BIO_puts(bio_out, "Отправляем k и m серверу...\n");

    tmpstr = BN_bn2dec(k);
    printf("k = %s\n", tmpstr);
    BIO_write(client->conn, tmpstr, strlen(tmpstr));
    BIO_write(client->conn, "\n", 1);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(m);
    printf("m = %s\n", tmpstr);
    BIO_write(client->conn, tmpstr, strlen(tmpstr));
    BIO_write(client->conn, "\n", 1);
    OPENSSL_free(tmpstr);
    
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

int serverMain(char ** argv) {
    int i;
    BIO * bio_listen = BIO_new_accept(*argv);
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
        HandleClient(BIO_pop(bio_listen));
    }
    BIO_free(bio_listen);
    return 0;
}

int clientConnect(Client * client, char * addr) {
    char tmpstr[1024];
    int bytes;

    client->conn = BIO_new_connect(addr);

    if (BIO_do_connect(client->conn) <= 0) {
        BIO_puts(bio_err, "Error connecting to server!\n");
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
    if (client->rsa == NULL)
        return 1;

    if(PEM_read_RSAPrivateKey(f, &client->rsa, password_callback, NULL) == 0)
        return 1;

    return 0;
}

int clientFree(Client client) {
    BIO_free(client.conn);
    RSA_free(client.rsa);
    BN_free(client.k);
    BN_free(client.m);
    return 0;
}

int clientMain(char ** argv) {
    
    Client client;

    if(clientConnect(&client, argv[0])) {
        BIO_puts(bio_err, "Не удалось установить соединение с сервером!\n");
        return 1;
    }

    if(clientReadKey(&client, argv[1])) {
        BIO_puts(bio_err, "Не удалось считать ключ!\n");
        return 1;
    }

    clientAct1(&client);
    
    clientFree(client);
    return 0;
}

#define using "using: rsazkp client|server <ip>:<port> <key>"

int main(int argc, char * argv[]) {

    int ret=1;

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    SSL_load_error_strings();
    SSL_library_init();
    
    if (argc != 4) {
        fprintf(stderr, "%s\n", using);
        return 1;
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

