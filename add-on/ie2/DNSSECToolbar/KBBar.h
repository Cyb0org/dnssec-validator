

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0555 */
/* at Tue Mar 11 12:30:34 2014
 */
/* Compiler settings for KBBar.idl:
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

#ifndef __KBBar_h__
#define __KBBar_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IKBBarBand_FWD_DEFINED__
#define __IKBBarBand_FWD_DEFINED__
typedef interface IKBBarBand IKBBarBand;
#endif 	/* __IKBBarBand_FWD_DEFINED__ */


#ifndef __KBBarBand_FWD_DEFINED__
#define __KBBarBand_FWD_DEFINED__

#ifdef __cplusplus
typedef class KBBarBand KBBarBand;
#else
typedef struct KBBarBand KBBarBand;
#endif /* __cplusplus */

#endif 	/* __KBBarBand_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __IKBBarBand_INTERFACE_DEFINED__
#define __IKBBarBand_INTERFACE_DEFINED__

/* interface IKBBarBand */
/* [unique][helpstring][dual][uuid][object] */ 


EXTERN_C const IID IID_IKBBarBand;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("38493F7F-2922-4C6C-9A9A-8DA2C940D0EE")
    IKBBarBand : public IDispatch
    {
    public:
    };
    
#else 	/* C style interface */

    typedef struct IKBBarBandVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IKBBarBand * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IKBBarBand * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IKBBarBand * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IKBBarBand * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IKBBarBand * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IKBBarBand * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IKBBarBand * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);
        
        END_INTERFACE
    } IKBBarBandVtbl;

    interface IKBBarBand
    {
        CONST_VTBL struct IKBBarBandVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IKBBarBand_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IKBBarBand_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IKBBarBand_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IKBBarBand_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IKBBarBand_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IKBBarBand_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IKBBarBand_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IKBBarBand_INTERFACE_DEFINED__ */



#ifndef __KBBarLib_LIBRARY_DEFINED__
#define __KBBarLib_LIBRARY_DEFINED__

/* library KBBarLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_KBBarLib;

EXTERN_C const CLSID CLSID_KBBarBand;

#ifdef __cplusplus

class DECLSPEC_UUID("669695BC-A811-4A9D-8CDF-BA8C795F261C")
KBBarBand;
#endif
#endif /* __KBBarLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


