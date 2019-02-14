#include "keygen.h"
#include "patch.h"
#include "helper.h"

void CMainWnd::Init()
{
    w = uiNewWindow("Navicat Keygen", 135, 140, 0);
    uiWindowOnClosing(w, onClosing, NULL);

    uiTab *tab = uiNewTab();
	uiWindowSetChild(w, uiControl(tab));

    uiBox *b;
    uiBox *c;
    uiGroup *g;

    b = uiNewVerticalBox();
    uiBoxSetPadded(b, 1);
    uiTabAppend(tab, "Keygen", uiControl(b));
	uiTabSetMargined(tab, 0, 1);
   
    // sn group
    c = uiNewVerticalBox();
    uiBoxSetPadded(c, 1);

    pid = uiNewCombobox();
    uiComboboxAppend(pid, "Navicat Premium");
    uiComboboxAppend(pid, "Navicat for MySQL");
    uiComboboxAppend(pid, "Navicat for PostgreSQL");
    uiComboboxAppend(pid, "Navicat for Oracle");
    uiComboboxAppend(pid, "Navicat for SQL Server");
    uiComboboxAppend(pid, "Navicat for SQLite");
    uiComboboxAppend(pid, "Navicat for MariaDB");
    uiComboboxAppend(pid, "Navicat for MongoDB");
    uiComboboxSetSelected(pid, 0);
    uiBoxAppend(c, uiControl(pid), 0);

    lang = uiNewCombobox();
    uiComboboxAppend(lang, "English");
    uiComboboxAppend(lang, "简体中文");
    uiComboboxAppend(lang, "繁體中文");
    uiComboboxAppend(lang, "日本語");
    uiComboboxAppend(lang, "Español");
    uiComboboxAppend(lang, "Français");
    uiComboboxAppend(lang, "Deutsch");
    uiComboboxAppend(lang, "한국어");
    uiComboboxAppend(lang, "Русский");
    uiComboboxAppend(lang, "Português");
    uiComboboxSetSelected(lang, 0);
    uiBoxAppend(c, uiControl(lang), 0);

    sn = uiNewEntry();
    uiEntrySetReadOnly(sn, 1);
    uiBoxAppend(c, uiControl(sn), 0);

    g = uiNewGroup("serial number");
    uiGroupSetMargined(g, 2);
    uiGroupSetChild(g, uiControl(c));
    uiBoxAppend(b, uiControl(g), 0);

    uiButton *btn;
    // Gen button
    btn = uiNewButton("Generate");
    uiButtonOnClicked(btn, onKeyGen, this);
    uiBoxAppend(b, uiControl(btn), 0);

    btn = uiNewButton("Patch");
    uiButtonOnClicked(btn, onPatch, this);
    uiBoxAppend(b, uiControl(btn), 0);

    b = uiNewVerticalBox();
    uiBoxSetPadded(b, 1);
    uiTabAppend(tab, "Activate", uiControl(b));
	uiTabSetMargined(tab, 1, 1);

    // register group
    name = uiNewEntry();
#if defined(_WIN32)
    uiEntrySetText(name, getenv("USERNAME"));
#elif defined(__APPLE__)
    uiEntrySetText(name, getenv("USER"));
#endif
    org = uiNewEntry();

    c = uiNewVerticalBox();
    uiBoxSetPadded(c, 1);
    uiBoxAppend(c, uiControl(name), 0);
    uiBoxAppend(c, uiControl(org), 0);

    g = uiNewGroup("register");
    uiGroupSetMargined(g, 2);
    uiGroupSetChild(g, uiControl(c));
    uiBoxAppend(b, uiControl(g), 0);

    lic = uiNewMultilineEntry();
    uiBoxAppend(b, uiControl(lic), 4);
    resp = uiNewMultilineEntry();
    uiMultilineEntrySetReadOnly(resp, 1);
    uiBoxAppend(b, uiControl(resp), 4);

    btn = uiNewButton("Active");
    uiButtonOnClicked(btn, onActive, this);
    uiBoxAppend(b, uiControl(btn), 0);

    uiControlShow(uiControl(w));
}

void CMainWnd::ErrBox(const char *format, ...)
{
    char m[260] = {};
    va_list args; 
    va_start(args, format);
    vsnprintf(m, sizeof(m), format, args);
    va_end(args);

    uiMsgBoxError(w, uiWindowTitle(w), m);
}

void CMainWnd::onPatch(uiButton *b, void *data)
{
    CMainWnd *pWnd = reinterpret_cast<CMainWnd*>(data);
    char* path = uiOpenFile(pWnd->w);
    if (!path) return;

    CAutoPtr<RSA> rsa = LoadRSA();
    if (!rsa) return pWnd->ErrBox("failed load rsa key");

    CAutoPtr<BIO> pb = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(pb, rsa)) 
        return pWnd->ErrBox("failed parse rsa key");
    char *key = NULL;
    int n = BIO_get_mem_data(pb, &key);

    CPatch s;
    if (!s.Open(path)) return pWnd->ErrBox("open execute failed");
    n = s.Patch3(key, n);
    if (n < 0) return pWnd->ErrBox("patch failed %d", n);
    uiMsgBox(pWnd->w, uiWindowTitle(pWnd->w), "patch success");
}

int CMainWnd::onClosing(uiWindow *, void *)
{
    uiQuit();
    return 1;
}

int main()
{
    CMainWnd w;

    uiInitOptions o = {};
    uiInit(&o);

    w.Init();

    uiMain();
    return 0;
}