#include "keygen.h"
#include "helper.h"

#include <openssl/des.h>
#include <openssl/evp.h>

#if defined(_WIN32)
static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
#else
static char table[] = "ABCDEFGH8JKLMN9PQRSTUVWXYZ234567";
#endif // _WIN32
static uint8_t des_key[] = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

enum Language {
    English,
    SimplifiedChinese,
    TraditionalChinese,
    Japanese,
    Polish,
    Spanish,
    French,
    German,
    Korean,
    Russian,
    Portuguese
};

void CMainWnd::onKeyGen(uiButton *, void *data)
{
    CMainWnd *pWnd = reinterpret_cast<CMainWnd*>(data);

    uint8_t tmp_key[18] = { 0x68, 0x2a };   //  must start with 0x68, 0x2a
    // random
    *((uint32_t*)(tmp_key + 2)) = rand();
    // language
    int language = uiComboboxSelected(pWnd->lang);
    switch (language) {
    case English:
        tmp_key[5] = 0xAC;       // English
        tmp_key[6] = 0x88;       // English
        break;
    case SimplifiedChinese:
        tmp_key[5] = 0xCE;       // Simplified Chinese
        tmp_key[6] = 0x32;       // Simplified Chinese
        break;
    case TraditionalChinese:
        tmp_key[5] = 0xAA;       // Traditional Chinese
        tmp_key[6] = 0x99;       // Traditional Chinese
        break;
    case Japanese:
        tmp_key[5] = 0xAD;       // Japanese
        tmp_key[6] = 0x82;       // Japanese
        break;
    case Polish:
        tmp_key[5] = 0xBB;       // Polish
        tmp_key[6] = 0x55;       // Polish
        break;
    case Spanish:
        tmp_key[5] = 0xAE;       // Spanish
        tmp_key[6] = 0x10;       // Spanish
        break;
    case French:
        tmp_key[5] = 0xFA;       // French
        tmp_key[6] = 0x20;       // French
        break;
    case German:
        tmp_key[5] = 0xB1;       // German
        tmp_key[6] = 0x60;       // German
        break;
    case Korean:
        tmp_key[5] = 0xB5;       // Korean
        tmp_key[6] = 0x60;       // Korean
        break;
    case Russian:
        tmp_key[5] = 0xEE;       // Russian
        tmp_key[6] = 0x16;       // Russian
        break;
    case Portuguese:
        tmp_key[5] = 0xCD;       // Portuguese
        tmp_key[6] = 0x49;       // Portuguese
        break;
    }
    // product id
    int product = uiComboboxSelected(pWnd->pid);
    switch (product) {
    case 0: // Navicat Premium
        tmp_key[7] = 0x65; 
        break;
    case 1: // Navicat for MySQL
        tmp_key[7] = 0x68; 
        break;
    case 2: // Navicat for PostgreSQL
        tmp_key[7] = 0x6C; 
        break;
    case 3: // Navicat for Oracle
        tmp_key[7] = 0x70; 
        break;
    case 4: // Navicat for SQL Server
        tmp_key[7] = 0x74; 
        break;
    case 5: // Navicat for SQLite
        tmp_key[7] = 0x78; 
        break;
    case 6: // Navicat for MariaDB
        tmp_key[7] = 0x7C; 
        break;
    case 7: // Navicat for MongoDB
        tmp_key[7] = 0x80; 
        break;
    }
    // version
    //  High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
    tmp_key[8] = 0xC0;
    tmp_key[9] = 0x32;   //  0xfd, 0xfc, 0xfb if you want to use not-for-resale license.

    DES_key_schedule schedule;
    DES_set_key_unchecked(&des_key, &schedule);
    DES_ecb_encrypt((const_DES_cblock*)(tmp_key + 2), (DES_cblock*)(tmp_key + 2), &schedule, DES_ENCRYPT);

    char serial[20] = {};
    int n = 0;
    // 生成序列号
    serial[n++] = table[tmp_key[0] >> 3];
    serial[n++] = table[(tmp_key[0] & 0x07) << 2 | tmp_key[1] >> 6];
    serial[n++] = table[tmp_key[1] >> 1 & 0x1F];
    serial[n++] = table[(tmp_key[1] & 0x1) << 4 | tmp_key[2] >> 4];
    serial[n++] = '-';
    serial[n++] = table[(tmp_key[2] & 0xF) << 1 | tmp_key[3] >> 7];
    serial[n++] = table[tmp_key[3] >> 2 & 0x1F];
    serial[n++] = table[(tmp_key[3] << 3 & 0x1F) | tmp_key[4] >> 5];
    serial[n++] = table[tmp_key[4] & 0x1F];
    serial[n++] = '-';
    serial[n++] = table[tmp_key[5] >> 3];
    serial[n++] = table[(tmp_key[5] & 0x07) << 2 | tmp_key[6] >> 6];
    serial[n++] = table[tmp_key[6] >> 1 & 0x1F];
    serial[n++] = table[(tmp_key[6] & 0x1) << 4 | tmp_key[7] >> 4];
    serial[n++] = '-';
    serial[n++] = table[(tmp_key[7] & 0xF) << 1 | tmp_key[8] >> 7];
    serial[n++] = table[tmp_key[8] >> 2 & 0x1F];
    serial[n++] = table[(tmp_key[8] << 3 & 0x1F) | tmp_key[9] >> 5];
    serial[n++] = table[tmp_key[9] & 0x1F];
    serial[n++] = '\0';

    uiEntrySetText(pWnd->sn, serial);
}

void CMainWnd::onActive(uiButton *b, void *data)
{
    CMainWnd *pWnd = reinterpret_cast<CMainWnd*>(data);
    char *lic = uiMultilineEntryText(pWnd->lic);
    if (lic == NULL || !lic[0]) return;
    // load private key
    Cipher rsa;
    int n = rsa.Load("./navicat.pem");
    if (n < 0) return pWnd->ErrBox("failed open pem %d", n);
    // decode base64
    n = strlen(lic);
    CAutoPtr<uint8_t> p = (uint8_t*)malloc(n * 2);
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        CAutoPtr<BIO> bmem = BIO_push(b64, BIO_new_mem_buf(lic, n));
        if (!strchr(lic, '\n')) BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
        n = BIO_read(bmem, p, n);
        if (n <= 0) return pWnd->ErrBox("failed decode request code %d", n);
        n = RSA_private_decrypt(n, p, p, rsa, RSA_PKCS1_PADDING);
        if (n <= 0) return pWnd->ErrBox("failed decrypt request code %d", n);
        p[n] = 0;
    }

    char *s = strstr(p.Get<char>(), "}");
    if (!s) return pWnd->ErrBox("request %s", p.Get<char>());
    printf("request code %s\n", p.Get<char>());
    // generate result
    n = sprintf(s, ",\"N\":\"%s\", \"O\":\"%s\", \"T\":%d }", 
        uiEntryText(pWnd->name), uiEntryText(pWnd->org), (int)time(NULL));
    n += s - p.Get<char>();

    // encrypt request code
    n = RSA_private_encrypt(n, p, p, rsa, RSA_PKCS1_PADDING);
    if (n <= 0) return pWnd->ErrBox("failed encrypt request code");
    BIO *bmem = BIO_new(BIO_s_mem());
    CAutoPtr<BIO> b64 = BIO_push(BIO_new(BIO_f_base64()), bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    if (!BIO_write(b64, p, n) || !BIO_flush(b64)) 
        return pWnd->ErrBox("failed encode request code");
    n = BIO_get_mem_data(bmem, &lic);
    lic[n] = 0;   

    printf("request %d code %s\n", n, lic);
    uiMultilineEntrySetText(pWnd->resp, lic);
}