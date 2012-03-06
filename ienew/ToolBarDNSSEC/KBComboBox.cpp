// KBComboBox.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h"
#include "KBComboBox.h"

#include "KBBar.h"
#include "KBBarBand.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

LPCTSTR c_strKBURLFormat = _T("http://support.microsoft.com/support/kb/articles/%s/%s/%s.asp");
LPCTSTR c_strKBSearchFormat = _T("http://search.support.microsoft.com/kb/psssearch.asp?SPR=msall&T=B&KT=ALL&T1=7d&LQ=%s&PQ=PastQuery&S=F&A=T&DU=C&FR=0&D=support&LPR=&LNG=ENG&CAT=Support&VRL=ENG&SA=ALLKB&VR=http%%3A%%2F%%2Fsupport.microsoft.com%%2Fsupport&Go.x=13&Go.y=27");

/////////////////////////////////////////////////////////////////////////////
// CKBComboBox

CKBComboBox::CKBComboBox()
{
}

CKBComboBox::~CKBComboBox()
{
}


BEGIN_MESSAGE_MAP(CKBComboBox, CComboBox)
	//{{AFX_MSG_MAP(CKBComboBox)
	ON_WM_CREATE()
	ON_NOTIFY_REFLECT(CBEN_BEGINEDIT, OnEditBegin)
	ON_CONTROL_REFLECT(CBN_CLOSEUP, OnCloseup)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CKBComboBox message handlers

// CanonicalizeString determines the string type and then cleans up the 
// string by stripping whitespace, etc.
// The "search type" has been designed for future extension.
CString CKBComboBox::CanonicalizeString(CString str, SearchType* psearchtype)
{
	CString outstr = str;

	// Strip beginning and end whitespace
	outstr.TrimLeft();
	outstr.TrimRight();

	// Strings entered into the edit box have two acceptable forms:
	// 1. "#Qxxxxxx" where x=[0..9] --> this is a direct Q# reference
	// 2. "anything else" --> general search of KB

	// Direct Q# reference
	if (str[0] == '#')
	{
		*psearchtype = st_QArticle;

		// Make sure string has typical length
		if (9 < str.GetLength() || 6 > str.GetLength())
		{
			outstr.Empty();
			return outstr;
		}

		// strip '#' sign
		outstr = outstr.Right(outstr.GetLength() - 1);

		// Make sure string is lowercase q + 6 numbers
		outstr.MakeLower();

	}
	else
	{
		*psearchtype = st_Keywords;
		// Escape string to be permissible on URL
		CString curStr = outstr;
		DWORD cchBuffer = 1;
		TCHAR temp;
		HRESULT hrUE = UrlEscape(curStr, &temp, &cchBuffer, NULL);
		LPTSTR pOutStr = outstr.GetBuffer(++cchBuffer);
		UrlEscape(curStr, pOutStr, &cchBuffer, NULL);
		outstr.ReleaseBuffer(cchBuffer);
	}

	return outstr;
}

bool CKBComboBox::NavigateToKB(CString strKB, SearchType searchtype)
{
	CString strURL;
	
	if (strKB.IsEmpty() || "" == strKB)
		return false;

	switch (searchtype)
	{
	case st_QArticle:
		strURL.Format(c_strKBURLFormat, strKB.Left(4), strKB.Mid(4, 1), strKB.Mid(5));
		TRACE(_T("Navigating to KB article: %s\n"), strURL);
		break;

	case st_Keywords:
		strURL.Format(c_strKBSearchFormat, strKB);
		TRACE(_T("Keyword search for: %s\n"), strKB);
		break;

	default:
		AfxMessageBox(_T("Check the syntax of your typed search request"));
		return false;
		break;
	}

	_variant_t varURL = _bstr_t(strURL);
	_variant_t varEmpty;
	m_pBand->m_pIE->Navigate2(&varURL, &varEmpty, &varEmpty, &varEmpty, &varEmpty);
	return true;
}

// Because the host owns the message processing, it will get all keyboard messages
// first.
// 1. We want to use the ENTER key to signal that the user is done in the edit control,
//    so we need to watch for VK_RETURN on WM_KEYUP
// 2. We also want the BACKSPACE, DELETE, END, ARROW keys to go to the edit control and
//	  not to the standard IE interfaces. We translate/dispatch these messages ourselves.
STDMETHODIMP CKBComboBox::TranslateAcceleratorIO(LPMSG pMsg)
{
USES_CONVERSION;
	int nVirtKey = (int)(pMsg->wParam);
	if (WM_KEYUP == pMsg->message && VK_RETURN == nVirtKey)
	{
		CString strEdit;
		CString strNewItem;
		GetWindowText(strEdit);
		SearchType searchtype;
		strNewItem = CanonicalizeString(strEdit, &searchtype);

		// Add item to control
		COMBOBOXEXITEM CBItem;
		memset(&CBItem, 0, sizeof(CBItem));
		CBItem.mask = CBEIF_TEXT | CBEIF_IMAGE | CBEIF_SELECTEDIMAGE | CBEIF_LPARAM;
		CBItem.iItem = 0;
		CBItem.pszText = (LPTSTR)(LPCTSTR)strNewItem;
		CBItem.cchTextMax = _tcslen((LPCTSTR)strNewItem);
		CBItem.iImage = ((DWORD)searchtype * 2);
		CBItem.iSelectedImage = CBItem.iImage + 1;
		CBItem.lParam = (DWORD)searchtype;

		int idx;
		TRACE(_T("Inserting Item: %s\n"), strNewItem);
		if (-1 == (idx = InsertItem(&CBItem)))
		{
			ASSERT(FALSE);
			DWORD dwError = ::GetLastError();
		}

		// Do action
		NavigateToKB(strNewItem, searchtype);

		return S_OK;
	}
	else if ((WM_KEYUP == pMsg->message || WM_KEYDOWN == pMsg->message) &&
				VK_BACK == nVirtKey || (VK_END <= nVirtKey && VK_DOWN >= nVirtKey) ||
				VK_DELETE == nVirtKey)
	{

		TranslateMessage(pMsg);
		DispatchMessage(pMsg);

		return S_OK;
	}
	else
		return S_FALSE;
}

void CKBComboBox::OnEditBegin( NMHDR * pNotifyStruct, LRESULT* result ) 
{
	// It is important that we signal site anytime we get a focus change to our band
	// Note that we don't have to do this when losing focus because whoever gets the
	// focus
	m_pBand->FocusChange(true);

	return;
}

int CKBComboBox::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	if (CComboBox::OnCreate(lpCreateStruct) == -1)
		return -1;
	
	SetDroppedWidth(200);

	m_ImageList.Create(IDR_COMBO_IMAGES, 16, 4, 0);
	int cnt = m_ImageList.GetImageCount();
	SetImageList(&m_ImageList);

	return 0;
}

// Called whenever user is done with dropdown
// Action: finds selected item and navigates to it
//			performs "history" of past searches
void CKBComboBox::OnCloseup() 
{
	CComboBox* pCombo = GetComboBoxCtrl();
	int idxSel = pCombo->GetCurSel();

	CString strItem;
	TCHAR buff[MAX_PATH];
	COMBOBOXEXITEM CBItem;
	memset(&CBItem, 0, sizeof(CBItem));
	CBItem.mask = CBEIF_TEXT | CBEIF_LPARAM;
	CBItem.cchTextMax = MAX_PATH;
	CBItem.pszText = buff;
	CBItem.iItem = idxSel;
	CBItem.iSelectedImage = 0;
	CBItem.lParam = 0;

	if (!GetItem(&CBItem))
	{
		ASSERT(FALSE);
		DWORD dwError = ::GetLastError();
	}
	if (-1 == CBItem.iItem)
		return;

	NavigateToKB(buff, (SearchType)CBItem.lParam);
}
