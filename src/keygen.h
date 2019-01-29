#ifndef _KEYGEN_H_
#define _KEYGEN_H_

#include <ui.h>

class CMainWnd
{
public:
    void Init();
    static int onClosing(uiWindow *w, void *data);
    static void onKeyGen(uiButton *b, void *data);
    static void onPatch(uiButton *b, void *data);

private:
    uiEntry *name, *org, *sn;
    uiCombobox *lang, *pid;
    uiWindow *w;
};

#endif // _KEYGEN_H_