/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator Add-on.

DNSSEC Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.

Some parts of these codes are based on the DNSSECVerify4IENav project
<http://cs.mty.itesm.mx/dnssecmx>, which is distributed under the Code Project
Open License (CPOL), see <http://www.codeproject.com/info/cpol10.aspx>.
***** END LICENSE BLOCK ***** */
/*
#if !defined(AFX_IETOOLBARCTRL_H__92D63B35_5805_4960_9770_B455E11FF4A7__INCLUDED_)
#define AFX_IETOOLBARCTRL_H__92D63B35_5805_4960_9770_B455E11FF4A7__INCLUDED_
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
*/
#pragma once
const int BITMAP_NUMBER = 7;
const int StatusBitmap[BITMAP_NUMBER] = {IDI_ICON_KEY_ACTION1 /*0*/, IDI_ICON_KEY_GREEN1 /*1*/,
	IDI_ICON_KEY_RED1 /*2*/, IDI_ICON_KEY_RED_IP1 /*3*/,  IDI_ICON_KEY_GREY1 /*4*/, 
	IDI_ICON_KEY_GREY_RC1 /*5*/, IDI_ICON_KEY_GREY_YT1 /*6*/};

const LPCTSTR stringtextCZ[BITMAP_NUMBER+1] = {_T("& DNSSEC Validátor\0") /*0*/, _T("& Zabezpeèeno DNSSEC\0") /*1*/,
	_T("& Neplatný DNSSEC podpis\0") /*2*/, _T("& Zabezpeèeno DNSSEC\0") /*3*/,  _T("& Neaktivní okno èi záložka\0") /*4*/, 
	_T("& Nezabezpeèeno DNSSEC\0") /*5*/, _T("& Stav DNSSEC neznámý\0") /*6*/, _T("& DNSSEC\0") /*7*/};

const LPCTSTR stringtextEN[BITMAP_NUMBER+1] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Secured by DNSSEC\0") /*1*/,
	_T("& Bogus DNSSEC signature\0") /*2*/, _T("& Secured by DNSSEC\0") /*3*/,  _T("& Inactive window or tab\0") /*4*/, 
	_T("& Not secured by DNSSEC\0") /*5*/, _T("& DNSSEC status unknown\0") /*6*/, _T("& DNSSEC\0") /*7*/};

const LPCTSTR stringtextDE[BITMAP_NUMBER+1] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Gesichert durch DNSSEC\0") /*1*/,
	_T("& Bogus DNSSEC Signatur\0") /*2*/, _T("& Gesichert durch DNSSEC\0") /*3*/,  _T("& Inaktive Fenster oder Tab\0") /*4*/, 
	_T("& Nicht gesichert durch DNSSEC\0") /*5*/, _T("& DNSSEC-Status unbekannt\0") /*6*/, _T("& DNSSEC\0") /*7*/};
		// Ein Fehler ist beim Abfragen des DNSSEC-Status aufgetreten
class CKBBarBand;
/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl window


class CKBToolBarCtrl : public CToolBarCtrl
{
// Construction
public:
	CKBToolBarCtrl();
	BEGIN_MSG_MAP(CToolBarCtrl)
	END_MSG_MAP()
// Attributes
public:
	CKBBarBand* m_pBand;

// Operations
public:
	bool Create(CRect rcClientParent, CWnd* pWndParent, CKBBarBand* pBand, HINSTANCE GHins);
	bool RepaintButton(int bindex, int iconindex);
	static LRESULT CALLBACK DialogProcAbout(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcDnssec(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcSettings(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	STDMETHOD(TranslateAcceleratorIO)(LPMSG pMsg);
	static bool CKBToolBarCtrl::ValidateIP(char *ipadd);
	static bool CKBToolBarCtrl::isip6(char *ipadd);
	static bool CKBToolBarCtrl::ValidateIP4(char *ipadd);
	static bool CKBToolBarCtrl::ValidateIP6(char *ipadd);
	void OnTbnDropDown(NMHDR *pNMHDR, LRESULT *pResult);
private:             ///< the hyperlink used in the 		 
		 // Implementation
public:
//	CKBComboBox m_wndCombo;
	virtual ~CKBToolBarCtrl();
	// Generated message map functions
protected:
	//LRESULT CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	afx_msg void OnCommand();
	//afx_msg void OnTbnDropDownToolBar1( NMHDR * pNotifyStruct, LRESULT * result );
	//afx_msg LRESULT onNotify(WPARAM wParam, LPNMHDR pNMHDR, BOOL& bHandled);
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

//#endif // !defined(AFX_IETOOLBARCTRL_H__92D63B35_5805_4960_9770_B455E11FF4A7__INCLUDED_)
