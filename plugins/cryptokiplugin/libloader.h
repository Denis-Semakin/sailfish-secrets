/* BSD 3-Clause License, see LICENSE.
 * This plugin is aimed to provide a high level interface to interact
 * with Cryto Token USB devices supported PKSC#11 standard.
 *
 * Copyright (C) 2018 Open Mobile Platform LLC.
 * Contact: Denis Semakin <d.semakin@omprussia.ru>
 * All rights reserved.
 */

#ifndef LIB_LOADER_H
#define LIB_LOADER_H

#include <iostream>
#include <string>
#include <memory>

#include <pkcs11.h>
#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcLibLoader)
#define PKCS11_FUNC(func)	loader.GetFunctions()->func

using Handle = std::unique_ptr<void, std::function<void(void*)>>;

class LibLoader
{
public:
    LibLoader();
    ~LibLoader();

    inline CK_FUNCTION_LIST_PTR GetFunctions() const noexcept
    {
        return m_pFunctions;
    }

    inline bool IsInitialized() const noexcept
    {
        return m_Initialized;
    }

    inline CK_SESSION_HANDLE getSession() const noexcept
    {
        return hSession;
    }

    const char * CKErr2Str(const CK_ULONG res);
    bool lock();
    bool unlock(const QByteArray &code);
    bool setLockCode(const QByteArray &oldCode, const QByteArray &newCode);

private:
   bool m_Initialized;
   Handle m_Handle;

   CK_SLOT_ID         slotId;
   CK_TOKEN_INFO      tokenInfo;
   CK_SESSION_HANDLE  hSession;

   CK_FUNCTION_LIST_PTR m_pFunctions;
};

#endif	// LIB_LOADER_H
