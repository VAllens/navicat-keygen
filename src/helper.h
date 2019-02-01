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
    template <typename N> N *Get() { return reinterpret_cast<N*>(pT); }
protected:
    T *pT;
};

#define DECLARE_TRAIT(t, f) template <>\
class CAutoPtrTrait<t>\
{\
public:\
    static void Close(t *p) { f(p); }\
};

DECLARE_TRAIT(BIO, BIO_free_all);
DECLARE_TRAIT(RSA, RSA_free);
DECLARE_TRAIT(BIGNUM, BN_free);

class Cipher : public CAutoPtr<RSA>
{
public:
    Cipher() : CAutoPtr<RSA>(RSA_new()) {}

    int Load(const char *path)
    {
        CAutoPtr<BIO> pb = BIO_new_file(path, "r");
        if (!pb) return -1;
        pT = PEM_read_bio_RSAPrivateKey(pb, &pT, NULL, NULL);
        return pT == NULL ? -2 : 0;
    }

    int Save(const char *path)
    {
        CAutoPtr<BIO> pb = BIO_new_file(path, "w");
        if (!pb) return -1;
        return PEM_write_bio_RSAPrivateKey(pb, pT, NULL, NULL, 0, NULL, NULL);
    }

    int Genkey(BIO *pb)
    {
        CAutoPtr<BIGNUM> bn = BN_new();
        BN_set_word(bn, RSA_F4);
        if (!RSA_generate_key_ex(pT, 2048, bn, NULL)) return -1;
        BIO_reset(pb);
        return PEM_write_bio_RSA_PUBKEY(pb, pT);
    }
};

#endif // _HELPER_H_