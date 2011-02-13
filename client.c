#include <string.h>

#include <openssl/ssl.h>

#include "bio.h"
#include "util.h"
#include "client.h"

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

int clientFree(Client * client) {

    BIO_free(client->conn);
    RSA_free(client->rsa);

    BN_free(client->k);
    BN_free(client->m);
    BN_free(client->C);
    BN_free(client->X);
    BN_free(client->M);
	
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

