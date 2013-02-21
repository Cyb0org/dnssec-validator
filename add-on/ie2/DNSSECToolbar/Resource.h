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
//
#define IDS_PROJNAME                    100
#define IDS_TOOLBARNAME                 1046
#define IDR_KBBARBAND			        1045
#define ID_BUTTON1                      32768
#define ID_BUTTON2	                    32769

// Key BMP
#define IDI_ICON_KEY_ACTION1            300
#define IDI_ICON_KEY_GREEN1             301
#define IDI_ICON_KEY_RED1               302
#define IDI_ICON_KEY_RED_IP1			303
#define IDI_ICON_KEY_GREY1              304
#define IDI_ICON_KEY_GREY_RC1           305
#define IDI_ICON_KEY_GREY_YT1           306
#define IDI_ICON_KEY_MIRROR				307
#define IDI_ICON_KEY_WHITE1				308

// key icon for DNSSEC dialog
#define IDI_ICON_KEY_GREEN2             401
#define IDI_ICON_KEY_RED2               402
#define IDI_ICON_KEY_ORANGE2            403
#define IDI_ICON_KEY_GREY2              404

// status bar key status text
#define	IDS_DNSSEC_KEY_TEXT_0 11110
#define	IDS_DNSSEC_KEY_TEXT_1 11111
#define	IDS_DNSSEC_KEY_TEXT_2 11112
#define	IDS_DNSSEC_KEY_TEXT_3 11113
#define	IDS_DNSSEC_KEY_TEXT_4 11114
#define	IDS_DNSSEC_KEY_TEXT_5 11115
#define	IDS_DNSSEC_KEY_TEXT_6 11116

//  Key Icon
#define IDI_ICON_KEY_GREEN              220
#define IDI_ICON_KEY_ACTION             221
#define IDI_ICON_KEY_GREY               222
#define IDI_ICON_KEY_GREY_RC            223
#define IDI_ICON_KEY_REDIP				224
#define IDI_ICON_KEY_RED                225
#define IDI_ICON_KEY_GREY_YT            226
#define IDI_ICON_KEY_WHITE				227
#define IDR_MENU_POPUP		            1000

	// Deafult
#define	IDS_PRE_TEXT_DOMAIN		101	
#define	IDS_PRE_TEXT_NODOMAIN	102
	// state 0 - GREEN 
#define IDS_STATE0_TEXT_TOOLTIP 103
#define	IDS_STATE0_TEXT_DOMAIN  104
#define	IDS_STATE0_TEXT_MAIN	105
	//state 1 - GREEN	
#define	IDS_STATE1_TEXT_TOOLTIP 106
#define	IDS_STATE1_TEXT_DOMAIN  107
#define	IDS_STATE1_TEXT_MAIN	108
	//state 2 - RED
#define	IDS_STATE2_TEXT_TOOLTIP 109
#define IDS_STATE2_TEXT_DOMAIN  110
#define	IDS_STATE2_TEXT_MAIN	111
	//state 3 - ORANGE
#define	IDS_STATE3_TEXT_TOOLTIP 112
#define	IDS_STATE3_TEXT_DOMAIN  113
#define	IDS_STATE3_TEXT_MAIN	114
	//state 4 - RED
#define	IDS_STATE4_TEXT_TOOLTIP 115
#define	IDS_STATE4_TEXT_DOMAIN  116
#define	IDS_STATE4_TEXT_MAIN	117
	//state 5 - GREY
#define	IDS_STATE5_TEXT_TOOLTIP 118
#define	IDS_STATE5_TEXT_DOMAIN  119
#define	IDS_STATE5_TEXT_MAIN	120
//state 6 - GREY
#define	IDS_STATE6_TEXT_TOOLTIP 121
#define	IDS_STATE6_TEXT_DOMAIN  122
#define	IDS_STATE6_TEXT_MAIN	123
	//state 7 - ORANGE
#define IDS_STATE7_TEXT_TOOLTIP 124
#define IDS_STATE7_TEXT_DOMAIN  125
#define	IDS_STATE7_TEXT_MAIN	126
	//state -1 - RED
#define	IDS_STATE01_TEXT_TOOLTIP 127
#define	IDS_STATE01_TEXT_DOMAIN  128
#define	IDS_STATE01_TEXT_MAIN	129
	// not used
#define IDS_STATE9_TEXT_TOOLTIP 130
#define	IDS_STATE9_TEXT_DOMAIN  131
#define	IDS_STATE9_TEXT_MAIN	132

	// init text for tooltip
#define IDS_NONE                        133
#define IDS_ADDON_INIT                  134
#define IDS_DNSSEC_ERROR_LABEL          135
#define IDS_DNSSEC_ERROR_FAIL			136
	// init text for toolbar
#define IDS_DNSSEC_OK			        137
#define IDS_DNSSEC_FAIL					138
#define IDS_IP_MATCH_TEXT				139
#define IDS_IP_MATCH_TEXT_NO			140
#define IDS_PRE_TEXT_ERROR				141
#define IDS_ERROR_TEXT_DOMAIN			142

// dialog Settings
#define IDD_DIALOG_MAIN                 1000
#define IDC_LIST_BOX                    1001
#define IDC_ADD_TEXT                    1002
#define IDC_EDIT                        1003
#define IDC_BUTTON2                     1005
#define IDC_DELETE_TEXT                 1005
#define IDC_COMBO                       1006
#define IDC_LB_COUNT                    1008
#define IDD_DIALOG_MAIN_ABOUT           1010
#define IDC_LINK						1011
#define IDC_R1							1012
#define IDC_R2							1013
#define IDC_R3							1014
#define	IDC_SHOWTEXT					1015
#define	IDC_TCP							1016
#define IDC_DEBUG						1017
#define IDC_CACHE						1018
#define IDC_IPv4						1020
#define IDC_IPv6						1021
#define IDC_IPv46						1022
#define IDC_R4							1023
#define IDC_IDDNSSEC					1024
#define IDC_DNSSEC_R					1025
#define IDC_DOM_ENABLE					1026
#define IDT_DOM_LIST					1027

// DNSSEC TEST messages in settings dialog
#define IDS_DNSSECTEST_IP				1050
#define IDS_DNSSECTEST_ERROR			1051
#define IDS_DNSSECTEST_BOGUS			1052
#define IDS_DNSSECTEST_OK				1053
#define IDS_DNSSECTEST_RUN				1054

// dialog DNSSEC status
#define IDD_DIALOG_DNSSEC			    1030
#define IDC_ST1							1031
#define IDC_ST2							1032
#define IDC_ST3							1033
#define IDC_ST4							1034
#define IDC_ST5							1035
#define IDC_ST6							1036
#define IDC_STIPB						1037
#define IDC_STIPV						1038
#define IDC_STIPBH						1039
#define IDC_STIPVH						1040

// menu items
#define ID_MENUPOPUP_OPTION1            32773
#define ID_MENUPOPUP_OPTION2            32772
#define ID_MORE_LINK1                   32778
#define ID_MORE_LINK2                   32779
#define ID_ENABLED                      32770
#define ID_ABOUT                        32771
#define ID_SET                          32773
#define ID_HOME                         32772

// Next default values for new objects
// 
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        211
#define _APS_NEXT_COMMAND_VALUE         32775
#define _APS_NEXT_CONTROL_VALUE         201
#define _APS_NEXT_SYMED_VALUE           144
#endif
#endif
