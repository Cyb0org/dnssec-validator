/* ***** BEGIN LICENSE BLOCK ***** 
Copyright 2013 CZ.NIC, z.s.p.o. 
File: DANE/TLSA library 
Authors: Martin Straka <martin.straka@nic.cz> 
         Karel Slany <karel.slany@nic.cz> 
 
This file is part of TLSA Validator 2 Add-on. 
 
TLSA Validator 2 Add-on is free software: you can redistribute it and/or 
modify it under the terms of the GNU General Public License as published by 
the Free Software Foundation, either version 3 of the License, or (at your 
option) any later version. 
 
TLSA Validator 2.Add-on is distributed in the hope that it will be useful, 
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
more details. 
 
You should have received a copy of the GNU General Public License along with 
TLSA Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>. 
 
Additional permission under GNU GPL version 3 section 7 
 
If you modify this Program, or any covered work, by linking or 
combining it with OpenSSL (or a modified version of that library), 
containing parts covered by the terms of The OpenSSL Project, the 
licensors of this Program grant you additional permission to convey 
the resulting work. Corresponding Source for a non-source form of 
such a combination shall include the source code for the parts of 
OpenSSL used as well as that of the covered work. 
***** END LICENSE BLOCK ***** */


/* This header file must be included before all others. */


#ifndef _CONFIG_RELATED_H_
#define _CONFIG_RELATED_H_


#ifdef __cplusplus
extern "C" {
#endif


#define TGT_DFLT 0 /* Default value. */
#define TGT_WIN 1 /* Being compiled for windows. */
#define TGT_OSX 2 /* Being compiled for Mac OS X. */


#ifndef TGT_SYSTEM
  #define TGT_SYSTEM TGT_DFLT
#endif /* !TGT_SYSTEM */


#ifdef __cplusplus
} /* extern "C" */
#endif


#endif /* !_CONFIG_RELATED_H_ */
