#if !defined(AFX_IETOOLBARCTRL_H__92D63B35_5805_4960_9770_B455E11FF4A7__INCLUDED_)
#define AFX_IETOOLBARCTRL_H__92D63B35_5805_4960_9770_B455E11FF4A7__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// IEToolBarCtrl.h : header file
//
//#include "KBComboBox.h"

const int BITMAP_NUMBER = 7;
const int StatusBitmap[BITMAP_NUMBER] = {IDI_ICON_KEY_ACTION1 /*0*/, IDI_ICON_KEY_GREEN1 /*1*/,
	IDI_ICON_KEY_RED1 /*2*/, IDI_ICON_KEY_ORANGE1 /*3*/,  IDI_ICON_KEY_GREY1 /*4*/, 
	IDI_ICON_KEY_GREY_RC1 /*5*/, IDI_ICON_KEY_GREY_YT1 /*6*/};

class CKBBarBand;

/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl window

class CKBToolBarCtrl : public CToolBarCtrl
{
// Construction
public:
	CKBToolBarCtrl();

// Attributes
public:
	CKBBarBand* m_pBand;

// Operations
public:
	bool Create(CRect rcClientParent, CWnd* pWndParent, CKBBarBand* pBand, WORD icon);
	bool RepaintButton(int bindex, int iconindex);
	STDMETHOD(TranslateAcceleratorIO)(LPMSG pMsg);

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CKBToolBarCtrl)
	//}}AFX_VIRTUAL

// Implementation
public:
//	CKBComboBox m_wndCombo;
	virtual ~CKBToolBarCtrl();

	// Generated message map functions
protected:
	afx_msg void OnCommand();
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_IETOOLBARCTRL_H__92D63B35_5805_4960_9770_B455E11FF4A7__INCLUDED_)
