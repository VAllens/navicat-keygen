#include "keygen.h"
#include "patch.h"

void CMainWnd::Init()
{
    w = uiNewWindow("Navicat Keygen", 135, 140, 0);
    uiWindowSetMargined(w, 1);
    uiWindowOnClosing(w, onClosing, NULL);

    uiBox *b = uiNewVerticalBox();
    uiBoxSetPadded(b, 1);
    uiWindowSetChild(w, uiControl(b));

    uiBox *c;
    uiGroup *g;

    // register group
    name = uiNewEntry();
    org = uiNewEntry();

    c = uiNewVerticalBox();
    uiBoxSetPadded(c, 1);
    uiBoxAppend(c, uiControl(name), 0);
    uiBoxAppend(c, uiControl(org), 0);

    g = uiNewGroup("register");
    uiGroupSetMargined(g, 2);
    uiGroupSetChild(g, uiControl(c));
    uiBoxAppend(b, uiControl(g), 0);

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

    uiControlShow(uiControl(w));
}

void CMainWnd::onPatch(uiButton *b, void *data)
{
    CMainWnd *pWnd = reinterpret_cast<CMainWnd*>(data);
    const char *pPath = uiOpenFile(pWnd->w);
    if (!pPath) return;

    CPatch s;
    const char *title = uiWindowTitle(pWnd->w);
    if (!s.Open(pPath))
    {
        uiMsgBoxError(pWnd->w, title, "open execute failed");
        return;
    }
    int r = s.Patch3();
    if (r < 0)
    {
        char msg[16] = {};
        sprintf(msg, "patch failed %d", r);
        uiMsgBoxError(pWnd->w, title, msg);
        return;
    }
    uiMsgBox(pWnd->w, title, "patch success");
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