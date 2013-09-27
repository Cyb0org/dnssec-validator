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
const int BITMAP_NUMBER = 8;
const int StatusBitmap[BITMAP_NUMBER] = {IDI_DNSSEC_ICON_ACTION1 /*0*/, IDI_DNSSEC_ICON_GREEN1 /*1*/,
	IDI_DNSSEC_ICON_RED1 /*2*/, IDI_DNSSEC_ICON_RED_IP1 /*3*/,  IDI_DNSSEC_ICON_GREY1 /*4*/, 
	IDI_DNSSEC_ICON_GREY_RC1 /*5*/, IDI_DNSSEC_ICON_GREY_YT1 /*6*/, IDI_DNSSEC_ICON_WHITE1 /*7*/};

const LPCTSTR stringtextCZ[BITMAP_NUMBER+1] = {_T("& DNSSEC Validátor\0") /*0*/, _T("& Zabezpeèeno DNSSEC\0") /*1*/,
	_T("& Neplatný DNSSEC podpis\0") /*2*/, _T("& Zabezpeèeno DNSSEC\0") /*3*/,  _T("& Neaktivní okno èi záložka\0") /*4*/, 
	_T("& Nezabezpeèeno DNSSEC\0") /*5*/, _T("& Stav DNSSEC neznámý\0") /*6*/, _T("& Neovìøeno DNSSEC\0") /*7*/, _T("& DNSSEC\0") /*8*/};

const LPCTSTR stringtextEN[BITMAP_NUMBER+1] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Secured by DNSSEC\0") /*1*/,
	_T("& Bogus DNSSEC signature\0") /*2*/, _T("& Secured by DNSSEC\0") /*3*/,  _T("& Inactive window or tab\0") /*4*/, 
	_T("& Not secured by DNSSEC\0") /*5*/, _T("& DNSSEC status unknown\0") /*6*/, _T("& Not verified by DNSSEC\0") /*7*/, _T("& DNSSEC\0") /*8*/};

const LPCTSTR stringtextDE[BITMAP_NUMBER+1] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Gesichert durch DNSSEC\0") /*1*/,
	_T("& Bogus DNSSEC Signatur\0") /*2*/, _T("& Gesichert durch DNSSEC\0") /*3*/,  _T("& Inaktive Fenster oder Tab\0") /*4*/, 
	_T("& Nicht gesichert durch DNSSEC\0") /*5*/, _T("& DNSSEC-Status unbekannt\0") /*6*/, _T("& Nicht durch DNSSEC geprüft\0") /*7*/, _T("& DNSSEC\0") /*8*/};
		// Ein Fehler ist beim Abfragen des DNSSEC-Status aufgetreten


const int BITMAP_NUMBER_TLSA = 8;
const int StatusBitmap2[BITMAP_NUMBER_TLSA] = {IDI_DNSSEC_ICON_ACTION1 /*0*/, IDI_DNSSEC_ICON_GREEN1 /*1*/,
	IDI_DNSSEC_ICON_RED1 /*2*/, IDI_DNSSEC_ICON_RED_IP1 /*3*/,  IDI_DNSSEC_ICON_GREY1 /*4*/, 
	IDI_DNSSEC_ICON_GREY_RC1 /*5*/, IDI_DNSSEC_ICON_GREY_YT1 /*6*/, IDI_DNSSEC_ICON_WHITE1 /*7*/};

const LPCTSTR stringtextCZ2[BITMAP_NUMBER_TLSA+1] = {_T("& TLSA Validátor\0") /*0*/, _T("& Certifikát odpovídá TLSA\0") /*1*/,
	_T("& Certifikát neodpovídá TLSA\0") /*2*/, _T("& Zabezpeèeno TLSA\0") /*3*/,  _T("& Neaktivní okno èi záložka\0") /*4*/, 
	_T("& Nezabezpeèeno TLSA\0") /*5*/, _T("& Stav TLSA neznámý\0") /*6*/, _T("& Neovìøeno TLSA\0") /*7*/, _T("& TLSA\0") /*8*/};

const LPCTSTR stringtextEN2[BITMAP_NUMBER_TLSA+1] = {_T("& TLSA Validator\0") /*0*/, _T("& Secured by TLSA\0") /*1*/,
	_T("& Bogus TLSA signature\0") /*2*/, _T("& Secured by TLSA\0") /*3*/,  _T("& Inactive window or tab\0") /*4*/, 
	_T("& Not secured by TLSA\0") /*5*/, _T("& TLSA status unknown\0") /*6*/, _T("& Not verified by TLSA\0") /*7*/, _T("& TLSA\0") /*8*/};

const LPCTSTR stringtextDE2[BITMAP_NUMBER_TLSA+1] = {_T("& TLSA Validator\0") /*0*/, _T("& Gesichert durch TLSA\0") /*1*/,
	_T("& Bogus TLSA Signatur\0") /*2*/, _T("& Gesichert durch TLSA\0") /*3*/,  _T("& Inaktive Fenster oder Tab\0") /*4*/, 
	_T("& Nicht gesichert durch TLSA\0") /*5*/, _T("& TLSA-Status unbekannt\0") /*6*/, _T("& Nicht durch TLSA geprüft\0") /*7*/, _T("& TLSA\0") /*8*/};
		// Ein Fehler ist beim Abfragen des TLSA-Status aufgetreten


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
	bool RepaintButtonDNSSEC(int bindex, int iconindex);
	bool RepaintButtonTLSA(int bindex, int iconindex);
	int WrongResolver(void);
	static LRESULT CALLBACK DialogProcAbout(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcDnssec(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcTlsa(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcSettings(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    STDMETHOD(TranslateAcceleratorIO)(LPMSG pMsg);
	static bool CKBToolBarCtrl::ValidateIP(char *ipadd);
	static bool CKBToolBarCtrl::isip6(char *ipadd);
	static bool CKBToolBarCtrl::ValidateIP4(char *ipadd);
	static bool CKBToolBarCtrl::ValidateIP6(char *ipadd);
	void OnTbnDropDown(NMHDR *pNMHDR, LRESULT *pResult);
	void OnTbnDropDown2(NMHDR *pNMHDR, LRESULT *pResult);
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
