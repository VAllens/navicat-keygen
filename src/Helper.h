#ifndef _HELPER_H_
#define _HELPER_H_

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

template <typename T>
class CHelpPtrTrait
{
public:
    static void Close(T *p) { free(p); }
};

template <typename T>
class CHelpPtr
{
public:
    CHelpPtr(T *p) : pT(p) {}
    ~CHelpPtr() { if (pT != NULL) CHelpPtrTrait<T>::Close(pT); }
    operator T*() { return pT; }
    T* operator ->() { return pT; }
    template <typename N> N *Get() { return reinterpret_cast<N*>(pT); }
protected:
    T *pT;
};

#define DECLARE_TRAIT(t, f, ...) template <>\
class CHelpPtrTrait<t>\
{\
public:\
    static void Close(t *p) { f(p, ##__VA_ARGS__); }\
};

DECLARE_TRAIT(BIO, BIO_free_all);
DECLARE_TRAIT(RSA, RSA_free);
DECLARE_TRAIT(BIGNUM, BN_free);

#endif // _HELPER_H_