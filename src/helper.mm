#include "helper.h"

#import <Foundation/Foundation.h>

RSA * LoadRSA()
{
    NSBundle *bundle = [NSBundle mainBundle];
    NSString *path = [bundle pathForResource:@"rpk" ofType:nil];
    const char *p = [path cStringUsingEncoding:NSUTF8StringEncoding];
    CAutoPtr<BIO> pb = BIO_new_file(p, "r");
    if (!pb) return NULL;

    RSA *rsa = NULL;
    PEM_read_bio_RSAPrivateKey(pb, &rsa, NULL, NULL);
    return rsa;
}