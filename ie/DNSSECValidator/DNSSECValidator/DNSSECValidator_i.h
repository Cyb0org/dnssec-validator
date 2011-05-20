

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0555 */
/* at Fri May 20 16:00:07 2011
 */
/* Compiler settings for DNSSECValidator.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 7.00.0555 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __DNSSECValidator_i_h__
#define __DNSSECValidator_i_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IDNSSECValidatorBHO_FWD_DEFINED__
#define __IDNSSECValidatorBHO_FWD_DEFINED__
typedef interface IDNSSECValidatorBHO IDNSSECValidatorBHO;
#endif 	/* __IDNSSECValidatorBHO_FWD_DEFINED__ */


#ifndef __DNSSECValidatorBHO_FWD_DEFINED__
#define __DNSSECValidatorBHO_FWD_DEFINED__

#ifdef __cplusplus
typedef class DNSSECValidatorBHO DNSSECValidatorBHO;
#else
typedef struct DNSSECValidatorBHO DNSSECValidatorBHO;
#endif /* __cplusplus */

#endif 	/* __DNSSECValidatorBHO_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __IDNSSECValidatorBHO_INTERFACE_DEFINED__
#define __IDNSSECValidatorBHO_INTERFACE_DEFINED__

/* interface IDNSSECValidatorBHO */
/* [unique][helpstring][nonextensible][dual][uuid][object] */ 


EXTERN_C const IID IID_IDNSSECValidatorBHO;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("D5F3AD9A-0C8E-40C5-9AE5-91292E2C5147")
    IDNSSECValidatorBHO : public IDispatch
    {
    public:
    };
    
#else 	/* C style interface */

    typedef struct IDNSSECValidatorBHOVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDNSSECValidatorBHO * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDNSSECValidatorBHO * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDNSSECValidatorBHO * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IDNSSECValidatorBHO * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IDNSSECValidatorBHO * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IDNSSECValidatorBHO * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IDNSSECValidatorBHO * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);
        
        END_INTERFACE
    } IDNSSECValidatorBHOVtbl;

    interface IDNSSECValidatorBHO
    {
        CONST_VTBL struct IDNSSECValidatorBHOVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IDNSSECValidatorBHO_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IDNSSECValidatorBHO_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IDNSSECValidatorBHO_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IDNSSECValidatorBHO_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IDNSSECValidatorBHO_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IDNSSECValidatorBHO_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IDNSSECValidatorBHO_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IDNSSECValidatorBHO_INTERFACE_DEFINED__ */



#ifndef __DNSSECValidatorLib_LIBRARY_DEFINED__
#define __DNSSECValidatorLib_LIBRARY_DEFINED__

/* library DNSSECValidatorLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_DNSSECValidatorLib;

EXTERN_C const CLSID CLSID_DNSSECValidatorBHO;

#ifdef __cplusplus

class DECLSPEC_UUID("022901CD-E83F-49F6-8960-96BB39E1A187")
DNSSECValidatorBHO;
#endif
#endif /* __DNSSECValidatorLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


