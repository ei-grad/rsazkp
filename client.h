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

