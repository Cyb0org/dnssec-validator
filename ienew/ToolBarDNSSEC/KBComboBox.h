if !defined(AFX_KBCOMBOBOX_H__EECD939F_3AC7_42BD_8D48_5D02B528691A__INCLUDED_)
#define AFX_KBCOMBOBOX_H__EECD939F_3AC7_42BD_8D48_5D02B528691A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// KBComboBox.h : header file
//

class CKBBarBand;

/////////////////////////////////////////////////////////////////////////////
// CKBComboBox window

typedef enum _tagSearchType {st_QArticle = 0, st_Keywords = 1} SearchType;

class CKBComboBox : public CComboBoxEx
{
// Construction
public:
	CKBComboBox();

// Attributes
public:
	CKBBarBand* m_pBand;

// Operations
public:
	STDMETHOD(TranslateAcceleratorIO)(LPMSG pMsg);

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CKBComboBox)
	//}}AFX_VIRTUAL

// Implementation
public:
	CImageList m_ImageList;
	bool NavigateToKB(CString strQ, SearchType searchtype);
	CString CanonicalizeString(CString str, SearchType* searchtype);
	virtual ~CKBComboBox();



	// Generated message map functions
protected:
	//{{AFX_MSG(CKBComboBox)
	afx_msg void OnEditBegin( NMHDR * pNotifyStruct, LRESULT* result );
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnCloseup();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_KBCOMBOBOX_H__EECD939F_3AC7_42BD_8D48_5D02B528691A__INCLUDED_)
