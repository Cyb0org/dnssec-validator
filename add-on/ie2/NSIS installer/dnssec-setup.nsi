# The NSIS (http://nsis.sourceforge.net) install script.
# This script is BSD licensed.
SetCompressor /solid /final lzma

!include LogicLib.nsh
!include MUI2.nsh
!include "FileFunc.nsh"

!define VERSION "2.1.0"
!define QUADVERSION "2.1.0.0"
!define guid '{669695BC-A811-4A9D-8CDF-BA8C795F261C}'

outFile "IE-dnssec-tlsa_validator-${VERSION}-windows.exe"
Name "DNSSEC/TLSA Validator 2.1.0 for IE"

# default install directory
installDir "$PROGRAMFILES\CZ.NIC\DNSSEC Validator 2.0"
installDirRegKey HKLM "Software\DNSSECValidator 2.0" "InstallLocation"
RequestExecutionLevel admin
#give credits to Nullsoft: BrandingText ""
VIAddVersionKey "ProductName" "DNSSEC/TLSA Validator 2.1.0"
VIAddVersionKey "CompanyName" "CZ.NIC Labs"
VIAddVersionKey "FileDescription" "(un)install the DNSSEC/TLSA Validator 2.1.0 for IE"
VIAddVersionKey "LegalCopyright" "Copyright 2013, CZ.NIC Labs"
VIAddVersionKey "FileVersion" "${QUADVERSION}"
VIAddVersionKey "ProductVersion" "${QUADVERSION}"
VIProductVersion "${QUADVERSION}"

# Global Variables
Var StartMenuFolder

# use ReserveFile for files required before actual installation
# makes the installer start faster
#ReserveFile "System.dll"
#ReserveFile "NsExec.dll"

!define MUI_ICON "key.ico"
!define MUI_UNICON "key.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "setup_top.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "setup_left.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "setup_left.bmp"
!define MUI_ABORTWARNING

!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of Internet Explorer DNSSEC/TLSA Validator plugin.$\r$\n$\nNote: It is recommended to close all running Internet Explorer windows before proceeding with the installation of the plugin.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY

!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\DNSSEC Validator 2.0"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "CZ.NIC\DNSSEC Validator 2.0"
!insertmacro MUI_PAGE_STARTMENU DNSSECStartMenu $StartMenuFolder

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the uninstallation of Internet Explorer DNSSEC/TLSA Validator plugin.$\r$\n$\nNote: It is recommended close all running Internet Explorer windows before proceeding with the uninstallation of the plugin.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English" 

section "-hidden.postinstall"
	# copy files
	setOutPath $INSTDIR
	File ".\ub_ds_windows-x86.dll"
  File ".\DANEcore-windows-x86.dll"
	File ".\IEdnssec.dll"
	File ".\key.ico"
	File ".\RegPlugin.bat"
	File ".\UnRegPlugin.bat"
  
	# store installation folder
	WriteRegStr HKLM "Software\DNSSEC Validator 2.0" "InstallLocation" "$INSTDIR"
  Delete "$LOCALAPPDATA\CZ.NIC\DNSSEC Validator 2.0\dnssec.ini"
	# register uninstaller
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "DisplayName" "DNSSEC Validator plugin 2.0"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "UninstallString" "$\"$INSTDIR\uninst.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "QuietUninstallString" "$\"$INSTDIR\uninst.exe$\" /S"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "NoRepair" "1"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "URLInfoAbout" "https://labs.nic.cz/page/1031/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "Publisher" "CZ.NIC Labs"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "Version" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "Contact" "CZ.NIC Labs"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "DisplayIcon" "$\"$INSTDIR\key.ico$\""
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" "EstimatedSize" "$0"
  WriteUninstaller "uninst.exe"


	# start menu items
	!insertmacro MUI_STARTMENU_WRITE_BEGIN DNSSECStartMenu
	CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "" "" "" "" "Uninstall DNSSEC/TLSA Validator 2.0 plugin for IE"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\RegPlugin.lnk" "$INSTDIR\RegPlugin.bat" "" "" "" "" "" "Manual registration of DNSSEC/TLSA Validator 2.0 plugin"
  CreateShortCut "$SMPROGRAMS\$StartMenuFolder\UnRegPlugin.lnk" "$INSTDIR\UnRegPlugin.bat" "" "" "" "" "" "Manual un-registration of DNSSEC/TLSA Validator 2.0 plugin"
	!insertmacro MUI_STARTMENU_WRITE_END

	# register DNSSEC toolbar
	RegDLL "$INSTDIR\IEdnssec.dll"
sectionEnd

# setup macros for uninstall functions.
!ifdef UN
!undef UN
!endif
!define UN "un."

# uninstaller section
section "un.Unbound"
	UnRegDLL "$INSTDIR\IEdnssec.dll"
  
  # deregister uninstall
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0"
  Delete "$INSTDIR\uninst.exe"   # delete self
  Delete "$INSTDIR\ub_ds_windows-x86.dll" 
  Delete "$INSTDIR\DANEcore-windows-x86.dll"    
	Delete "$INSTDIR\IEdnssec.dll"
	Delete "$INSTDIR\key.ico"
	Delete "$INSTDIR\RegPlugin.bat"
	Delete "$INSTDIR\UnRegPlugin.bat"
  Delete "$LOCALAPPDATA\CZ.NIC\DNSSEC Validator 2.0\dnssec.ini"
	RMDir "$INSTDIR"

	# start menu items
	!insertmacro MUI_STARTMENU_GETFOLDER DNSSECStartMenu $StartMenuFolder
	Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\RegPlugin.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\UnRegPlugin.lnk"
	RMDir "$SMPROGRAMS\$StartMenuFolder"
	DeleteRegKey HKLM "Software\DNSSECValidator 2.0"
sectionEnd
