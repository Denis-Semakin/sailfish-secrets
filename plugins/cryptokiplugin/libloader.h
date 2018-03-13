/* BSD 3-Clause License, see LICENSE.
 * This plugin is aimed to provide a high level interface to interact
 * with Cryto Token USB devices supported PKSC#11 standard.
 *
 * Copyright (C) 2018 Open Mobile Platform LLC.
 * Contact: Denis Semakin <d.semakin@omprussia.ru>
 * All rights reserved.
 */

#ifndef _LIB_LOADER_H
#define _LIB_LOADER_H

#include <iostream>
#include <string>

#include <pkcs11.h>

class LibLoader
{
private:
	bool	m_Initialized;
	void	*m_Handle;

	CK_SLOT_ID      SlotId;
	CK_TOKEN_INFO   tokenInfo;
	CK_SESSION_HANDLE   hSession;

	CK_FUNCTION_LIST_PTR m_pFunctions;

public:
	LibLoader();
	~LibLoader();

	CK_FUNCTION_LIST_PTR GetFunctions() const
	{
		return m_pFunctions;
	}

	bool IsInitialized() const
	{
		return m_Initialized;
	}

	void *GetHandle()
	{
		return m_Handle;
	}

	CK_SESSION_HANDLE getSession() const
	{
		return hSession;
	}

	std::string CKErr2Str(CK_ULONG res);

	static LibLoader& GetLibLoader();
};

#define PKCS11_FUNC(func)	loader.GetFunctions()->func

#endif	// _LIB_LOADER_H
