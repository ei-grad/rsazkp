#include <openssl/ssl.h>

#include "util.h"
#include "server.h"

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

int serverReadKey(Server * server, char * key) {

    FILE * f;
    
    if ((f = fopen(key, "r")) == NULL) {
        fprintf(stderr, "Can't open file %s!\n", key);
        return 1;
    }
    
    server->rsa = RSA_new();
    if (server->rsa == NULL)
        return 1;

    if(PEM_read_RSA_PUBKEY(f, &server->rsa, (pem_password_cb *) password_callback, NULL) == 0) {
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
    BN_free(server->C);
    BN_free(server->X);
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
    BIO_free(bio_listen);
    return 0;
}

