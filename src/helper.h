#ifndef _HELPER_H_
#define _HELPER_H_

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string.h>

template <typename T>
class CAutoPtrTrait
{
public:
    static void Close(T *p) { free(p); }
};

template <typename T>
class CAutoPtr
{
public:
    CAutoPtr(T *p) : pT(p) {}
    ~CAutoPtr() { if (pT != NULL) CAutoPtrTrait<T>::Close(pT); }
    operator T*() { return pT; }
    T** operator &() { return &pT; }
    T* operator ->() { return pT; }
    template <typename N> N *Get() { return reinterpret_cast<N*>(pT); }
protected:
    T *pT;
};

#define DECLARE_TRAIT(t, f, ...) template <>\
class CAutoPtrTrait<t>\
{\
public:\
    static void Close(t *p) { f(p, ##__VA_ARGS__); }\
};

DECLARE_TRAIT(BIO, BIO_free_all);
DECLARE_TRAIT(RSA, RSA_free);
DECLARE_TRAIT(BIGNUM, BN_free);

RSA * LoadRSA();

#endif // _HELPER_H_