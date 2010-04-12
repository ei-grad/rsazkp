/*
 * Copyright (c) 2009-2010 Andrew S. Grigorev <andrew@ei-grad.ru>
 * Chelyabinsk State University
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
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ui.h>


typedef struct server {
    BIO * conn;
    RSA * rsa;
    // Act 1
    BIGNUM * k;
    BIGNUM * m;
    // Act 2
    BIGNUM * C;
    // Act 3
    BIGNUM * X;
} Server;


typedef struct client {
    BIO * conn;
    RSA * rsa;
    // Act 1
    BIGNUM * k;
    BIGNUM * m;
    // Act2
    BIGNUM * C;
    // Act3
    BIGNUM * M;
    BIGNUM * X;
} Client;


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
        
        if (res->neg) {
            BN_add(res, res, n);
        }

        ret = 0;
    }

    BN_free(d);
    BN_free(x);
    BN_free(y);

    return ret;
}


int clientAct1(Client * client) {
    
    int bytes;
    char buf[1024];
    char * tmpstr;

    printf("\n==== Этап 1 ====\n\n");

    BIGNUM * k = BN_new();
    BIGNUM * m = BN_new();

    BIGNUM * phy = BN_new();
    BIGNUM * tmp1 = BN_new();
    BIGNUM * tmp2 = BN_new();
    BIGNUM * bn_one = BN_new();

    BN_one(bn_one);

    BN_sub(tmp1, client->rsa->p, bn_one);
    BN_sub(tmp2, client->rsa->q, bn_one);

    BN_CTX * ctx = BN_CTX_new();
    BN_mul(phy, tmp1, tmp2, ctx);

    tmpstr = BN_bn2dec(phy);
    printf("phy(n) = %s\n", tmpstr);
    OPENSSL_free(tmpstr);
    
    do {
        BN_rand_range(k, phy);
        tmpstr = BN_bn2dec(k);
        printf("Ищем обратный по умножению к числу %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    } while(GetMultiplicativeInverse(m, k, phy));

    BN_mod_mul(m, m, client->rsa->e, phy, ctx);
    BN_CTX_free(ctx);

    client->k = k;
    client->m = m;
    
    BIO_puts(bio_out, "Отправляем k и m серверу...\n");

    tmpstr = BN_bn2dec(k);
    printf("k = %s\n", tmpstr);
    BIO_write(client->conn, tmpstr, strlen(tmpstr)+1);
    OPENSSL_free(tmpstr);

    bytes = BIO_read(client->conn, buf, 1024);
    buf[bytes] = 0;
    if (strcmp(buf, "OK") != 0)
        return 1;

    tmpstr = BN_bn2dec(m);
    printf("m = %s\n", tmpstr);
    BIO_write(client->conn, tmpstr, strlen(tmpstr)+1);
    OPENSSL_free(tmpstr);
    

    bytes = BIO_read(client->conn, buf, 1024);
    buf[bytes] = 0;
    if (strcmp(buf, "OK") != 0)
        return 1;

    
    return 0;
}

int serverAct1(Server * server) {
    int bytes;
    char buf[1024];
    char * bufptr = buf;
    char * tmpstr;

    printf("\n==== Этап 1 ====\n\n");
    
    server->k = BN_new();
    server->m = BN_new();

    bytes = BIO_read(server->conn, buf, 1024);
    buf[bytes] = 0;
    BN_dec2bn(&server->k, buf);
    tmpstr = BN_bn2dec(server->k);
    printf("k = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    BIO_puts(server->conn, "OK");

    bytes = BIO_read(server->conn, buf, 1024);
    buf[bytes] = 0;
    BN_dec2bn(&server->m, buf);
    tmpstr = BN_bn2dec(server->m);
    printf("m = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    BIO_puts(server->conn, "OK");

    return 0;
}

int clientAct2(Client * client) {

    int bytes;
    char * tmpstr;
    char buf[1024];

    printf("\n==== Этап 2 ====\n\n");

    client->C = BN_new();
    BN_rand_range(client->C, client->rsa->n);

    tmpstr = BN_bn2dec(client->C);
    printf("Шифртекст: %s\n", tmpstr);
    BIO_puts(client->conn, tmpstr);
    OPENSSL_free(tmpstr);
    
    bytes = BIO_read(client->conn, buf, 1024);
    buf[bytes] = 0;
    if (strcmp(buf, "OK") != 0)
        return 1;
   client->rsa->n,  
    printf("Шифртест передан.\n");

    return 0;
}

int serverAct2(Server * server) {

    int bytes;
    char buf[1024];
    
    printf("\n==== Этап 2 ====\n\n");

    bytes = BIO_read(server->conn, buf, 1024);
    buf[bytes] = 0;

    printf("Получен шифртекст: %s\n", buf);

    server->C = BN_new();

    if (!BN_dec2bn(&server->C, buf)) {
        fprintf(stderr, "Ошибка при получении шифртекста!");
        BIO_puts(server->conn, "ERR");
        return 1;
    }
    
    BIO_puts(server->conn, "OK");
    printf("Шифртест принят.\n");
    
    return 0;
}

int clientAct3(Client * client) {

    int bytes;
    char buf[1024];
    char * tmpstr;

    printf("\n==== Этап 3 ====\n\n");

    client->M = BN_new();
    client->X = BN_new();

    BN_CTX * ctx = BN_CTX_new();

    BN_mod_exp(client->M, client->C, client->rsa->d, client->rsa->n, ctx);
    
    tmpstr = BN_bn2dec(client->M);
    printf("M = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    BN_mod_exp(client->X, client->M, client->k, client->rsa->n, ctx);

    tmpstr = BN_bn2dec(client->X);
    BIO_puts(client->conn, tmpstr);
    printf("X = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    BIGNUM * x = BN_new();
    BN_mod_exp(x, client->C, client->rsa->d, client->rsa->n, ctx);
    BN_mod_exp(x, x, client->rsa->e, client->rsa->n, ctx);
    tmpstr = BN_bn2dec(x);
    printf("x = %s\n", tmpstr);
    OPENSSL_free(tmpstr);
    
    bytes = BIO_read(client->conn, buf, 1024);
    buf[bytes] = 0;
    if (strcmp(buf, "OK") != 0) {
        printf("%s\n", buf);
        return 1;
    }
    
    printf("X передан.\n");
    
    BN_CTX_free(ctx);
    return 0;
}

int serverAct3(Server * server) {

    int bytes;
    char buf[1024];
    
    printf("\n==== Этап 3 ====\n\n");

    bytes = BIO_read(server->conn, buf, 1024);
    buf[bytes] = 0;

    printf("Получен X: %s\n", buf);

    server->X = BN_new();

    if (!BN_dec2bn(&server->X, buf)) {
        fprintf(stderr, "Ошибка при получении X!");
        BIO_puts(server->conn, "ERR");
        return 1;
    }
    
    BIO_puts(server->conn, "OK");
    printf("X принят.\n");
    
    return 0;
}

int clientAct4(Client * client) {

    int bytes;
    char buf[1024];

    printf("\n==== Этап 4 ====\n\n");

    BIO_puts(client->conn, "How do you do?");

    bytes = BIO_read(client->conn, buf, 1024);
    buf[bytes] = 0;
    if (strcmp(buf, "OK") != 0) {
        printf("Сервер отверг доказательство!\n");
        return 1;
    }
    
    printf("Сервер принял доказательство.\n");
    return 0;
}

int serverAct4(Server * server) {

    int bytes;
    char buf[1024];
    char * tmpstr;
    int ret = 1;
    
    printf("\n==== Этап 4 ====\n\n");
    
    bytes = BIO_read(server->conn, buf, 1024);
    buf[bytes] = 0;
    if (strcmp(buf, "How do you do?") != 0)
        return 1;
    
    BIGNUM * x = BN_new();
    BN_CTX * ctx = BN_CTX_new();

    BN_mod_exp(x, server->X, server->m, server->rsa->n, ctx);

    tmpstr = BN_bn2dec(x);
    printf("x = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    if ( BN_cmp(x, server->C) == 0 ) {
        BIO_puts(server->conn, "OK");
        printf("Проверка пройдена. Клиенту отправлено подтверждение.\n");
        ret = 0;
    } else {
        BIO_puts(server->conn, "ERR");
        printf("Тест провален. Клиент оповещен о неудаче.\n");
    }
    
    BN_free(x);
    BN_CTX_free(ctx);
    
    return ret;
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

    if(clientAct1(&client)) {
        printf("Ошибка при прохождении первого этапа!\n");
        return 1;
    }

    if(clientAct2(&client)) {
        printf("Ошибка при прохождении второго этапа!\n");
        return 1;
    }
    
    if(clientAct3(&client)) {
        printf("Ошибка при прохождении третьего этапа!\n");
        return 1;
    }

    if(clientAct4(&client)) {
        printf("Ошибка при прохождении четвертого этапа!\n");
        return 1;
    }

    printf("Доказательство завершено!\n");

    clientFree(&client);
    return 0;
}

int serverHandleClient(Server * server){
    
    if(serverAct1(server)) {
        printf("Ошибка при прохождении первого этапа!\n");
        return 1;
    }
    if(serverAct2(server)) {
        printf("Ошибка при прохождении второго этапа!\n");
        return 1;
    }
    if(serverAct3(server)) {
        printf("Ошибка при прохождении третьего этапа!\n");
        return 1;
    }

    if(serverAct4(server)) {
        printf("Ошибка при прохождении четвертого этапа!\n");
        return 1;
    }

    printf("Проверка завершена!\n\n");

    return 0;
}

int serverMain(char ** argv) {

    Server server;
    int i;
    
    if (serverReadKey(&server, argv[1])) {
        fprintf(stderr, "Can't read key from file %s!", argv[1]);
        return 1;
    }

    BIO * bio_listen = BIO_new_accept(argv[0]);
    BIO_set_bind_mode(bio_listen, BIO_BIND_REUSEADDR);

    /* First call to BIO_accept() sets up accept BIO */
    if(BIO_do_accept(bio_listen) <= 0) {
        fprintf(stderr, "Error setting up accept\n");
        return 1;
    }

    for(i=0; i < 10; i++){

        /* Wait for incoming connection */
        if(BIO_do_accept(bio_listen) <= 0) {
            fprintf(stderr, "Ошибка подключения!\n");
            return 1;
        }
        fprintf(stderr, "Соединение установлено.\n");

        server.conn = BIO_pop(bio_listen);

        if(serverHandleClient(&server)) {
            printf("Клиент не смог доказать знание закрытого ключа RSA!\n\n\n");
        } else {
            printf("Клиент доказал знание закрытого ключа RSA.\n\n\n");
        }
        BIO_free(server.conn);
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

    if(PEM_read_RSAPrivateKey(f, &client->rsa, (pem_password_cb *) password_callback, NULL) == 0)
        return 1;

    char * tmpstr;

    tmpstr = BN_bn2dec(client->rsa->n);
    printf("Модуль: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(client->rsa->e);
    printf("Публичная экспонента: %s\n", tmpstr);
    OPENSSL_free(tmpstr);
    
    tmpstr = BN_bn2dec(client->rsa->d);
    printf("Секретная экспонента: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    printf("&p = %x\n", client->rsa->p);
    if (client->rsa->p){
        tmpstr = BN_bn2dec(client->rsa->p);
        printf("p = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }
    
    printf("&q = %x\n", client->rsa->q);
    if (client->rsa->q){
        tmpstr = BN_bn2dec(client->rsa->q);
        printf("q = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }

    return 0;
}

int serverReadKey(Server * server, char * key) {

    FILE * f;
    
    if ((f = fopen(key, "r")) == NULL) {
        fprintf(stderr, "Can't open file %s!\n", key);
        return 1;
    }
    
    server->rsa = RSA_new();
    if (server->rsa == NULL)
        return 1;

    if(PEM_read_RSAPublicKey(f, &server->rsa, (pem_password_cb *) password_callback, NULL) == 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char * tmpstr;

    tmpstr = BN_bn2dec(server->rsa->n);
    printf("Модуль: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(server->rsa->e);
    printf("Публичная экспонента: %s\n", tmpstr);
    OPENSSL_free(tmpstr);
    
    printf("&p = %x\n", server->rsa->p);
    if (server->rsa->p){
        tmpstr = BN_bn2dec(server->rsa->p);
        printf("p = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }

    return 0;
}

int serverFree(Server * server) {
    BIO_free(server->conn);
    RSA_free(server->rsa);
    BN_free(server->k);
    BN_free(server->m);
}

int clientFree(Client * client) {
    BIO_free(client->conn);
    RSA_free(client->rsa);
    BN_free(client->k);
    BN_free(client->m);
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

