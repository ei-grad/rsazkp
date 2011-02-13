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

#include "bio.h"
#include "client.h"
#include "server.h"

#define using "using: rsazkp client|server <ip>:<port> <key>"

int main(int argc, char * argv[]) {

    int ret = 1;

    init_bio();

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

