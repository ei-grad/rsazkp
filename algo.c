#include <openssl/bn.h>

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

