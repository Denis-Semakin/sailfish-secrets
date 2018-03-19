/* BSD 3-Clause License, see LICENSE.
 * This plugin is aimed to provide a high level interface to interact
 * with Cryto Token USB devices supported PKSC#11 standard.
 *
 * Copyright (C) 2018 Open Mobile Platform LLC.
 * Contact: Denis Semakin <d.semakin@omprussia.ru>
 * All rights reserved.
 */

#include <string.h>
#include <dlfcn.h>
#include <errno.h>

#include <vector>
#include <string>

#include <QtCore/QDebug>
#include <QtCore/QByteArray>

#include "libloader.h"

namespace {

// This is pre-defined path for common purpose OpenSC PKCS11 library
#define	DEFAULT_PKCS11_LIB_PATH	"/usr/lib/opensc-pkcs11.so"
// This is path to Aladdin's PKCS11 library
#define	ALADDIN_PKCS11_LIB_PATH	"/usr/lib/libjcPKCS11-2.so"

#define CALL_P11LIB(func)	GetFunctions()->func

const std::array<const char *, 2> PKCS11Libs = {
	DEFAULT_PKCS11_LIB_PATH,
	ALADDIN_PKCS11_LIB_PATH
};

} // anonymous namespace

const char *
LibLoader::CKErr2Str(CK_ULONG res)
{
	switch (res) {
	case CKR_OK:
		return "CKR_OK";
	case CKR_CANCEL:
		return "CKR_CANCEL";
	case CKR_HOST_MEMORY:
		return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID:
		return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR:
		return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED:
		return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD:
		return "CKR_ARGUMENTS_BAD";
	case CKR_NO_EVENT:
		return "CKR_NO_EVENT";
	case CKR_NEED_TO_CREATE_THREADS:
		return "CKR_NEED_TO_CREATE_THREADS";
	case CKR_CANT_LOCK:
		return "CKR_CANT_LOCK";
	case CKR_ATTRIBUTE_READ_ONLY:
		return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE:
		return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID:
		return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID:
		return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_DATA_INVALID:
		return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE:
		return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR:
		return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY:
		return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED:
		return "CKR_DEVICE_REMOVED";
	case CKR_ENCRYPTED_DATA_INVALID:
		return "CKR_ENCRYPTED_DATA_INVALID";
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	case CKR_FUNCTION_CANCELED:
		return "CKR_FUNCTION_CANCELED";
	case CKR_FUNCTION_NOT_PARALLEL:
		return "CKR_FUNCTION_NOT_PARALLEL";
	case CKR_FUNCTION_NOT_SUPPORTED:
		return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID:
		return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE:
		return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT:
		return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_NOT_NEEDED:
		return "CKR_KEY_NOT_NEEDED";
	case CKR_KEY_CHANGED:
		return "CKR_KEY_CHANGED";
	case CKR_KEY_NEEDED:
		return "CKR_KEY_NEEDED";
	case CKR_KEY_INDIGESTIBLE:
		return "CKR_KEY_INDIGESTIBLE";
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_KEY_NOT_WRAPPABLE:
		return "CKR_KEY_NOT_WRAPPABLE";
	case CKR_KEY_UNEXTRACTABLE:
		return "CKR_KEY_UNEXTRACTABLE";
	case CKR_MECHANISM_INVALID:
		return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID:
		return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID:
		return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE:
		return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED:
		return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT:
		return "CKR_PIN_INCORRECT";
	case CKR_PIN_INVALID:
		return "CKR_PIN_INVALID";
	case CKR_PIN_LEN_RANGE:
		return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_EXPIRED:
		return "CKR_PIN_EXPIRED";
	case CKR_PIN_LOCKED:
		return "CKR_PIN_LOCKED";
	case CKR_SESSION_CLOSED:
		return "CKR_SESSION_CLOSED";
	case CKR_SESSION_COUNT:
		return "CKR_SESSION_COUNT";
	case CKR_SESSION_HANDLE_INVALID:
		return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	case CKR_SESSION_READ_ONLY:
		return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS:
		return "CKR_SESSION_EXISTS";
	case CKR_SESSION_READ_ONLY_EXISTS:
		return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	case CKR_SIGNATURE_INVALID:
		return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE:
		return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE:
		return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT:
		return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT:
		return "CKR_TOKEN_NOT_PRESENT";
	case CKR_TOKEN_NOT_RECOGNIZED:
		return "CKR_TOKEN_NOT_RECOGNIZED";
	case CKR_TOKEN_WRITE_PROTECTED:
		return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_USER_ALREADY_LOGGED_IN:
		return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN:
		return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED:
		return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID:
		return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_USER_TOO_MANY_TYPES:
		return "CKR_USER_TOO_MANY_TYPES";
	case CKR_WRAPPED_KEY_INVALID:
		return "CKR_WRAPPED_KEY_INVALID";
	case CKR_WRAPPED_KEY_LEN_RANGE:
		return "CKR_WRAPPED_KEY_LEN_RANGE";
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		return "CKR_WRAPPING_KEY_HANDLE_INVALID";
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		return "CKR_WRAPPING_KEY_SIZE_RANGE";
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		return "CKR_RANDOM_SEED_NOT_SUPPORTED";
	case CKR_RANDOM_NO_RNG:
		return "CKR_RANDOM_NO_RNG";
	case CKR_DOMAIN_PARAMS_INVALID:
		return "CKR_DOMAIN_PARAMS_INVALID";
	case CKR_BUFFER_TOO_SMALL:
		return "CKR_BUFFER_TOO_SMALL";
	case CKR_SAVED_STATE_INVALID:
		return "CKR_SAVED_STATE_INVALID";
	case CKR_INFORMATION_SENSITIVE:
		return "CKR_INFORMATION_SENSITIVE";
	case CKR_STATE_UNSAVEABLE:
		return "CKR_STATE_UNSAVEABLE";
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	case CKR_MUTEX_BAD:
		return "CKR_MUTEX_BAD";
	case CKR_MUTEX_NOT_LOCKED:
		return "CKR_MUTEX_NOT_LOCKED";
	case CKR_VENDOR_DEFINED:
		return "CKR_VENDOR_DEFINED";
	}
	return "unknown PKCS11 error";
}

bool
LibLoader::lock()
{
    CK_RV ret = C_Logout(hSession);
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "Error: " << CKErr2Str(ret);
	return false;
    }

    ret = C_CloseSession(hSession);
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "Error: " << CKErr2Str(ret);
	return false;
    }

    return true;
}

bool
LibLoader::unlock(const QByteArray &code)
{
    CK_RV	ret;
    CK_ULONG	slotCount = 0;

    // Steps are: C_Initialize(), C_GetSlotList(), C_GetTokenInfo
    //		  C_OpenSession(), C_Login()

   for (const char *lib : PKCS11Libs)
   {
	qCCritical(lcLibLoader) << "Trying to load: " << lib;

	Handle handle(dlopen(lib, RTLD_LAZY), dlclose);
	if (handle == nullptr)
	{
	    qCCritical(lcLibLoader) << "Load library failed: " << lib;
	    continue;
	}

	CK_C_GetFunctionList flist =
		reinterpret_cast<CK_C_GetFunctionList>(dlsym(handle.get(),
							 "C_GetFunctionList"));
	if (flist == nullptr)
	{
	    qCCritical(lcLibLoader) << "C_GetFunctionList not found in module";
	    continue;
	}

	ret = flist(&m_pFunctions);
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_GetFunctionList failed: 0x" <<  std::hex << ret;
	    continue;
	}

	ret = CALL_P11LIB(C_Initialize(nullptr));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_Initialize error " << CKErr2Str(ret);
	    continue;
	}

	ret = CALL_P11LIB(C_GetSlotList(CK_TRUE, nullptr, &slotCount));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_GetSlotList error " << CKErr2Str(ret);
	    continue;
	}

	// One slot == one reader
	if (slotCount == 0) //No slots
	{
	    qCCritical(lcLibLoader) << "No slots";
	    continue;
	}

	ret = CALL_P11LIB(C_GetSlotList(CK_TRUE, &slotId, &slotCount));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_GetSlotList error " << CKErr2Str(ret);
	    continue;
	}

	ret = CALL_P11LIB(C_GetTokenInfo(slotId, &tokenInfo));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_GetTokenInfo error " << CKErr2Str(ret);
	    continue;
	}

	ret = CALL_P11LIB(C_OpenSession(slotId, (CKF_SERIAL_SESSION | CKF_RW_SESSION),
			  0, 0, &hSession));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_OpenSession error " << CKErr2Str(ret);
	    continue;
	}

	CK_CHAR_PTR Pin = reinterpret_cast<CK_CHAR_PTR>(const_cast<char *>(code.data()));

	ret = CALL_P11LIB(C_Login(hSession, CKU_USER, Pin, code.length()));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_Login error " << CKErr2Str(ret);
	    continue;
	}

	m_Handle = std::move(handle);
	m_Initialized = true;
	break;
    } //for (...)

    return true;
}

bool
LibLoader::setLockCode(const QByteArray &oldCode, const QByteArray &newCode)
{
    const CK_CHAR_PTR
    oldPin = reinterpret_cast<CK_CHAR_PTR>(const_cast<char *>(oldCode.data()));
    const CK_CHAR_PTR
    newPin = reinterpret_cast<CK_CHAR_PTR>(const_cast<char *>(newCode.data()));
    const CK_RV ret = CALL_P11LIB(C_SetPIN(hSession, oldPin, oldCode.length(),
					   newPin, newCode.length()));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "Error: " << CKErr2Str(ret);
	return false;
    }

    return true;
}

LibLoader::LibLoader()
	: m_Initialized(false)
	, m_Handle(nullptr)
	, m_pFunctions(nullptr)
{
}

LibLoader::~LibLoader()
{
    if (m_Initialized)
    {
	CALL_P11LIB(C_Logout(hSession));
	CALL_P11LIB(C_CloseSession(hSession));
	CALL_P11LIB(C_Finalize(nullptr));
	m_Initialized = false;
    }
}

