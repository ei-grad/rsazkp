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

