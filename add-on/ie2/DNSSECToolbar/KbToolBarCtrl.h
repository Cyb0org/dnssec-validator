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
const int BITMAP_NUMBER = 19;
const int StatusBitmap[BITMAP_NUMBER] = {IDI_BMP_INIT0, IDI_BMP_INIT1, IDI_BMP_INIT2, IDI_BMP_INIT3, IDI_BMP_INIT4,
			IDI_BMP_INIT5, IDI_BMP_INIT6, IDI_BMP_INIT7, IDI_BMP_INIT8, IDI_BMP_INIT9, IDI_BMP_INIT10, IDI_BMP_INIT11,
			IDI_BMP_INIT12, IDI_BMP_INIT13, IDI_BMP_INIT14, IDI_BMP_INIT15, IDI_BMP_INIT16, IDI_BMP_INIT17, IDI_BMP_INIT18
};

const LPCTSTR stringtextCZ[BITMAP_NUMBER+2] = {_T("& DNSSEC Valid·tor\0") /*0*/, _T("& NeovÏ¯eno DNSSEC\0") /*1*/,
	_T("& Stav DNSSEC nezn·m˝\0") /*2*/, _T("& Zjiöùov·nÌ DNSSEC zabezpeËenÌ\0") /*3*/,  _T("& NezabezpeËeno DNSSEC\0") /*4*/, 
	_T("& ZabezpeËeno DNSSEC\0") /*5*/, _T("& Neplatn˝ DNSSEC podpis\0") /*6*/, _T("& ZabezpeËeno DNSSEC\0") /*7*/,
	_T("& NeovÏ¯eno DNSSEC\0") /*8*/, _T("& TLSA Valid·tor\0") /*9*/, _T("& TLSA validace vypnuta\0") /*10*/,
	_T("& Stav TLSA nezn·m˝\0") /*11*/, _T("& ProbÌh· validace TLSA\0") /*12*/,  _T("& NezabezpeËeno DNSSEC\0") /*13*/, 
	_T("& Certifik·t odpovÌd· TLSA\0") /*14*/, _T("& Certifik·t neodpovÌd· TLSA\0") /*15*/, _T("& NenÌ HTTPS spojenÌ\0") /*16*/,
	_T("& Neexistuje TLSA z·znam\0") /*17*/, _T("& Neplatn˝ DNSSEC podpis\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};

const LPCTSTR stringtextEN[BITMAP_NUMBER+2] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Not verified by DNSSEC\0") /*1*/,
	_T("& DNSSEC status unknown\0") /*2*/, _T("& Retrieving DNSSEC status\0") /*3*/,  _T("& Not secured by DNSSEC\0") /*4*/, 
	_T("& Secured by DNSSEC\0") /*5*/, _T("& Bogus DNSSEC signature\0") /*6*/, _T("& Secured by DNSSEC\0") /*7*/,
	_T("& Not verified by DNSSEC\0") /*8*/, _T("& TLSA Validator\0") /*9*/, _T("& TLSA validation disabled\0") /*10*/,
	_T("& TLSA status unknown\0") /*11*/, _T("& TLSA validation in progress\0") /*12*/,  _T("& Not secured by DNSSEC\0") /*13*/, 
	_T("& Certificate corresponds to TLSA\0") /*14*/, _T("& Certificate doesn't correspond to TLSA\0") /*15*/, _T("& No HTTPS connection\0") /*16*/,
	_T("& TLSA record does not exist\0") /*17*/, _T("& Bogus DNSSEC signature\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};


const LPCTSTR stringtextDE[BITMAP_NUMBER+2] = {_T("& DNSSEC-Validator\0") /*0*/, _T("& Nicht durch DNSSEC gepr¸ft\0") /*1*/,
	_T("& DNSSEC-Zustand unbekannt\0") /*2*/, _T("& Erwerbung des DNSSEC-Zustandes\0") /*3*/,  _T("& Nicht durch DNSSEC gesichert\0") /*4*/, 
	_T("& Gesichert durch DNSSEC\0") /*5*/, _T("& Ung¸ltige DNSSEC-Signatur\0") /*6*/, _T("& Gesichert durch DNSSEC\0") /*7*/,
	_T("& Nicht durch DNSSEC gepr¸ft\0") /*8*/, _T("& TLSA-Validator\0") /*9*/, _T("& TLSA Validierung ausgeschaltet\0") /*10*/,
	_T("& TLSA Status unbekannt\0") /*11*/, _T("& TLSA Validierung wird durchgef¸hrt\0") /*12*/,  _T("& Nicht durch DNSSEC gesichert\0") /*13*/, 
	_T("& Zertifikat entspricht TLSA\0") /*14*/, _T("& Zertifikat entspricht nicht TLSA\0") /*15*/, _T("& Keine HTTPS Verbindung\0") /*16*/,
	_T("& Kein TLSA Eintrag vorhanden\0") /*17*/, _T("& Ung¸ltige DNSSEC Signatur\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};
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
