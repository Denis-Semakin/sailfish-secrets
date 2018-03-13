/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 *
 * This plugin is aimed to provide a high level interface to interact
 * with Cryto Token USB devices supported PKSC#11 standard.
 *
 * Copyright (C) 2018 Open Mobile Platform LLC.
 * Contact: Denis Semakin <d.semakin@omprussia.ru>
 * All rights reserved.
 */

#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"
#include "cryptokiplugin.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>

#include <fstream>
#include <cstdlib>

//TODO: Need Initialize() method
#define	P11LOADER_FUNC(func) \
    (loader)->GetFunctions()->func

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

using namespace Sailfish::Crypto;

Daemon::Plugins::CryptokiPlugin::CryptokiPlugin(QObject *parent)
    : QObject(parent), CryptoPlugin(), loader(&LibLoader::GetLibLoader())
{

}

Daemon::Plugins::CryptokiPlugin::~CryptokiPlugin()
{

}

Result
Daemon::Plugins::CryptokiPlugin::seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate)
{
    Q_UNUSED(callerIdent)
    Q_UNUSED(csprngEngineName)
    Q_UNUSED(seedData)
    Q_UNUSED(entropyEstimate)

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::generateAndStoreKey(
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(kpgParams);
    Q_UNUSED(skdfParams);

    CK_BBOOL		bToken = TRUE;
    CK_BBOOL		bTrue = CK_TRUE;
    CK_BBOOL		bFalse = CK_FALSE;
    CK_MECHANISM	mech = {
	CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE STR_CRYPTO_PRO_A[] = {
	0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01
    };
    CK_BYTE STR_CRYPTO_PRO_GOST3411[] = {
	0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01
    };

    // Secret Key attributes
    // Note! All attributes can be and/or should be set up by &kpgParams for
    // example
    CK_ATTRIBUTE privKeyAttribs[] = {
        { CKA_TOKEN, (CK_VOID_PTR)&bToken, sizeof(bToken) }, // in token
	// Secret Key label
        { CKA_LABEL, (CK_VOID_PTR)"Private key", (CK_ULONG)strlen("Private key") },
	// Key pair type. rfc 4357
        { CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)STR_CRYPTO_PRO_A, sizeof(STR_CRYPTO_PRO_A) },
	// hidden from user unless enter PIN-code
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
	// for sign
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
    };

    CK_ATTRIBUTE pubKeyAttribs[] = {
	// in token
        { CKA_TOKEN, (CK_VOID_PTR)&bToken, sizeof(bToken) },
	// Public Key label
        { CKA_LABEL, (CK_VOID_PTR)"Public key", (CK_ULONG)strlen("Public key") },
	// Key pair type. rfc 4357
        { CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)STR_CRYPTO_PRO_A, sizeof(STR_CRYPTO_PRO_A) },
	// Hash alg standard
        { CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)STR_CRYPTO_PRO_GOST3411, sizeof(STR_CRYPTO_PRO_GOST3411) },
	// hidden from user unless enter PIN-code
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
	// for verify
        { CKA_VERIFY,  &bTrue,  sizeof(bTrue) },
    };

    // Keys descriptors
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

    CK_RV ret = P11LOADER_FUNC(
		C_GenerateKeyPair(loader->getSession(), &mech,
				  &pubKeyAttribs[0],
				  sizeof(pubKeyAttribs) /sizeof(CK_ATTRIBUTE),
				  &privKeyAttribs[0],
				  sizeof(privKeyAttribs)/sizeof(CK_ATTRIBUTE),
				  &hPublicKey, &hPrivateKey));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    QByteArray PublicKeyData  = QByteArray::number(static_cast<qulonglong>(hPublicKey));
    QByteArray PrivateKeyData = QByteArray::number(static_cast<qulonglong>(hPrivateKey));

    keyMetadata->setPublicKey(PublicKeyData);
    keyMetadata->setPrivateKey(PrivateKeyData);

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
        Key *key)
{
    // A found id will be returned here
    CK_OBJECT_HANDLE	KeyHandle = 0;
    CK_ULONG		KeyobjCount = 0;
    CK_ULONG		KeyClass;
    CK_BBOOL		bTrue = CK_TRUE;

    // Object
    CK_ULONG KeyType = CKK_RSA;	//Temporary RSA, in future test GOST

    if (keyComponents & Key::PublicKeyData)
    {
	KeyClass = CKO_PUBLIC_KEY;
    }
    else if (keyComponents & Key::PrivateKeyData)
    {
	KeyClass = CKO_PRIVATE_KEY;
    }

    CK_ATTRIBUTE KeySearchAttribs[] = {
	{ CKA_CLASS, &KeyClass, sizeof(KeyClass) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, (CK_VOID_PTR)identifier.name().toLatin1().data(),
				(CK_ULONG)identifier.name().toLatin1().length() },
        { CKA_KEY_TYPE, &KeyType, sizeof(KeyType) }
    };


    CK_RV ret = P11LOADER_FUNC(C_FindObjectsInit(loader->getSession(),
						 KeySearchAttribs,
						 sizeof(KeySearchAttribs) / sizeof(CK_ATTRIBUTE)));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    ret = P11LOADER_FUNC(C_FindObjects(loader->getSession(),
					    &KeyHandle, 1, &KeyobjCount));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    ret = P11LOADER_FUNC(C_FindObjectsFinal(loader->getSession()));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    if (!KeyobjCount) {
	    std::cerr << "No key found" << std::endl;
	    return Result(Result::Failed);
    }

    QByteArray KeyData  = QByteArray::number(static_cast<qulonglong>(KeyHandle));
    key->setSecretKey(KeyData);

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::storedKeyIdentifiers(
        QVector<Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("Operation is not supported"));
}

Key
Daemon::Plugins::CryptokiPlugin::getFullKey(
        const Sailfish::Crypto::Key &key)
{
    return key;
}

Result
Daemon::Plugins::CryptokiPlugin::generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            QByteArray *randomData)
{
	Q_UNUSED(callerIdent);
	Q_UNUSED(csprngEngineName);

	CK_RV ret = P11LOADER_FUNC(C_GenerateRandom(loader->getSession(),
			reinterpret_cast<unsigned char *>(randomData->data()),
			numberBytes));
	if (ret != CKR_OK)
	{
		std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
		return Result(Result::Failed);
	}

	return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            bool *validated)
{
    Q_UNUSED(chain)
    Q_UNUSED(validated)
    return Result(Result::UnsupportedOperation,
		  QLatin1String("Operations is not supported"));
}

//FIXME if wrong. By default a generated key will NOT be stored on token
Result
Daemon::Plugins::CryptokiPlugin::generateKey(
            const Key &keyTemplate,
            const KeyPairGenerationParameters &kpgParams,
            const KeyDerivationParameters &skdfParams,
            Key *key)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(skdfParams);
    Q_UNUSED(key);

    CK_BBOOL	bTrue = CK_TRUE;

    if (kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairUnknown)
    {

	CK_BBOOL	bToken = TRUE;
	CK_BBOOL	bFalse = CK_FALSE;
	CK_MECHANISM	mech = {
	    CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_BYTE		STR_CRYPTO_PRO_A[] = {
	    0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01
	};
	CK_BYTE		STR_CRYPTO_PRO_GOST3411[] = {
	    0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01
	};

	// Secret Key attributes
	// Note! All attributes can be and should be set up by &kpgParams for
	// example
	CK_ATTRIBUTE privKeyAttribs[] =	{
	    { CKA_TOKEN, (CK_VOID_PTR) &bToken, sizeof(bToken) }, // in token
	    // Secret Key label
	    { CKA_LABEL, (CK_VOID_PTR)"Private key", (CK_ULONG)strlen("Private key") },
	    // Key pair type. rfc 4357
	    { CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) STR_CRYPTO_PRO_A,
							sizeof(STR_CRYPTO_PRO_A) },
	    // hidden from user unless enter PIN-code
	    { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
	    // for sign
	    { CKA_SIGN, &bTrue, sizeof(bTrue) },
	};

	CK_ATTRIBUTE pubKeyAttribs[] = {
	    // in token
	    { CKA_TOKEN, (CK_VOID_PTR) &bToken, sizeof(bToken) },
	    // Public Key label
	    { CKA_LABEL, (CK_VOID_PTR)"Public key", (CK_ULONG) strlen("Public key") },
	    // Key pair type. rfc 4357
	    { CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)STR_CRYPTO_PRO_A,
							sizeof(STR_CRYPTO_PRO_A) },
	    // Hash alg standard
	    { CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)STR_CRYPTO_PRO_GOST3411,
							sizeof(STR_CRYPTO_PRO_GOST3411) },
	    // hidden from user unless enter PIN-code
	    { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
	    // for verify
	    { CKA_VERIFY,  &bTrue,  sizeof(bTrue) },
	};

	// Keys descriptors
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

	CK_RV ret = P11LOADER_FUNC(
		    C_GenerateKeyPair(loader->getSession(), &mech,
				      &pubKeyAttribs[0],
				      sizeof(pubKeyAttribs) / sizeof(CK_ATTRIBUTE),
				      &privKeyAttribs[0],
				      sizeof(privKeyAttribs) / sizeof(CK_ATTRIBUTE),
				      &hPublicKey, &hPrivateKey));
	if (ret != CKR_OK)
	{
		std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
		return Result(Result::Failed);
	}

	QByteArray PublicKeyData  =
		QByteArray::number(static_cast<qulonglong>(hPublicKey));
	QByteArray PrivateKeyData =
		QByteArray::number(static_cast<qulonglong>(hPrivateKey));

	key->setPublicKey(PublicKeyData);
	key->setPrivateKey(PrivateKeyData);
    }
    else
    {
	CK_OBJECT_HANDLE SessionKeyHandle;
	CK_MECHANISM mech = {CKM_GOST28147_KEY_GEN, NULL, 0};
	CK_BYTE STR_CRYPTO_PRO_GOST28147_A[] = {0x06, 0x07, 0x2a, 0x85, 0x03,
						0x02, 0x02, 0x1f, 0x01};
	CK_ATTRIBUTE KeyTemplate[] = {
		{CKA_GOST28147_PARAMS, STR_CRYPTO_PRO_GOST28147_A, sizeof(STR_CRYPTO_PRO_GOST28147_A)},
		{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
		{CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)}
	};

	CK_RV ret = P11LOADER_FUNC(C_GenerateKey(loader->getSession(),
						      &mech, KeyTemplate,
			sizeof(KeyTemplate) / sizeof(CK_ATTRIBUTE),
			&SessionKeyHandle));
	if (ret != CKR_OK)
	{
	    std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	    return Result(Result::Failed);
	}

	QByteArray KeyData = QByteArray::number(static_cast<qulonglong>(SessionKeyHandle));
	key->setSecretKey(KeyData);
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::sign(
            const QByteArray &data,
            const Key &key,
            CryptoManager::SignaturePadding padding,
            CryptoManager::DigestFunction digestFunction,
            QByteArray *signature)
{
    Q_UNUSED(padding)
    Q_UNUSED(digestFunction)
//    if (digestFunction != CryptoManager::DigestFunction::DigestGost)
//	    return Result(Result::UnsupportedOperation,
//			 QLatin1String("The plugin supports only GOST"));

    char sign[64];
    CK_ULONG nSignatureLength = sizeof(sign);

    //NOTE: One should choose a correct mech from in params
    CK_OBJECT_HANDLE	hPrivateKey = key.privateKey().toULong();
    CK_MECHANISM	mech = {
        CKM_GOSTR3410_WITH_GOSTR3411_2012_256, nullptr, 0
    };

    CK_RV ret = P11LOADER_FUNC(C_SignInit(loader->getSession(),
					  &mech, hPrivateKey));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    CK_BYTE_PTR
    Data2Sign = reinterpret_cast<CK_BYTE_PTR>(const_cast<char *>(data.data()));

    CK_BYTE_PTR pSign = reinterpret_cast<CK_BYTE_PTR>(sign);

    ret = P11LOADER_FUNC(C_Sign(loader->getSession(), Data2Sign,
				data.length(), pSign, &nSignatureLength));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    signature->append(sign, nSignatureLength);

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::verify(
	    const QByteArray &signature,
            const QByteArray &data,
            const Key &key,
            CryptoManager::SignaturePadding padding,
            CryptoManager::DigestFunction digest,
            bool *verified)
{
    Q_UNUSED(padding)
    Q_UNUSED(digest)

//    if (digest != CryptoManager::DigestFunction::DigestGost)
//	    return Result(Result::UnsupportedOperation,
//			 QLatin1String("The plugin supports only GOST"));

    CK_OBJECT_HANDLE    hPublicKey = key.publicKey().toULong();
    CK_MECHANISM        mech = {
	CKM_GOSTR3410_WITH_GOSTR3411_2012_256, nullptr, 0
    };

    CK_RV ret = P11LOADER_FUNC(C_VerifyInit(loader->getSession(),
					    &mech, hPublicKey));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    CK_BYTE_PTR
    Data2Verify = reinterpret_cast<CK_BYTE_PTR>(const_cast<char *>(data.data()));

    CK_BYTE_PTR
    Sign = reinterpret_cast<CK_BYTE_PTR>(const_cast<char *>(signature.data()));

    ret = P11LOADER_FUNC(C_Verify(loader->getSession(), Data2Verify,
				  data.length(), Sign, signature.length()));
    if (ret != CKR_OK)
    {
	*verified = false;
	if (ret == CKR_SIGNATURE_INVALID)
	{
	    return Result(Result::Succeeded);
	}

	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    *verified = true;

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            CryptoManager::BlockMode blockMode,
            CryptoManager::EncryptionPadding padding,
            QByteArray *encrypted)
{
    Q_UNUSED(blockMode);
    Q_UNUSED(padding);

    long unsigned int iv_length = static_cast<long unsigned int>(iv.length());
    char *iv_data = const_cast<char *>(iv.data());

    CK_MECHANISM mech = {
	CKM_GOST28147, //can be configuired, may be by blockMode
	iv_data,
	iv_length
    };

    CK_RV ret = P11LOADER_FUNC(C_EncryptInit(loader->getSession(), &mech,
					     key.secretKey().toULong()));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    CK_BYTE_PTR
    PlainText = reinterpret_cast<CK_BYTE_PTR>(const_cast<char *>(data.data()));

    CK_ULONG
    PlainTextLen = static_cast<CK_ULONG>(data.length());

    CK_BYTE_PTR
    EncData = reinterpret_cast<CK_BYTE_PTR>(encrypted->data());

    CK_ULONG EncDataLen;

    ret = P11LOADER_FUNC(C_Encrypt(loader->getSession(), PlainText,
				   PlainTextLen, EncData, &EncDataLen));

    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            CryptoManager::BlockMode blockMode,
            CryptoManager::EncryptionPadding padding,
            QByteArray *decrypted)
{
    Q_UNUSED(blockMode);
    Q_UNUSED(padding);

    long unsigned int iv_length = static_cast<long unsigned int>(iv.length());
    char *iv_data = const_cast<char *>(iv.data());

    CK_MECHANISM mech = {
	CKM_GOST28147, //Can be configuired I suppose, may be by blockMode
	iv_data,
	iv_length
    };

    CK_RV ret = P11LOADER_FUNC(C_DecryptInit(loader->getSession(), &mech,
					     key.secretKey().toULong()));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    CK_BYTE_PTR
    EncData = reinterpret_cast<CK_BYTE_PTR>(const_cast<char *>(data.data()));

    CK_ULONG
    EncDataLen = static_cast<CK_ULONG>(data.length());

    CK_BYTE_PTR
    PlainText = reinterpret_cast<CK_BYTE_PTR>(decrypted->data());
    CK_ULONG	PlainTextLen;


    ret = P11LOADER_FUNC(C_Decrypt(loader->getSession(), EncData,
				   EncDataLen, PlainText, &PlainTextLen));

    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::calculateDigest(
		const QByteArray &data,
		CryptoManager::SignaturePadding padding,
		CryptoManager::DigestFunction digestFunction,
		QByteArray *digest)
{
    Q_UNUSED(padding)

    long unsigned int len = 0;
    char dig[65] = {0};
    CK_MECHANISM mech;

    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;

    switch (digestFunction)
    {
	case CryptoManager::DigestFunction::DigestGost94:
	     mech.mechanism = CKM_GOSTR3411;
	     len = 32;
	     break;
	case CryptoManager::DigestFunction::DigestGost12_256:
	     mech.mechanism = CKM_GOSTR3411_12_256;
	     len = 32;
	     break;
	case CryptoManager::DigestFunction::DigestGost12_512:
	     mech.mechanism = CKM_GOSTR3411_12_512;
	     len = 64;
	     break;
	default:
	     return Result(Result::UnsupportedOperation,
			   QLatin1String("The Cryptoki plugin supports ONLY GOST"));

    }

    CK_RV ret = P11LOADER_FUNC(C_DigestInit(loader->getSession(), &mech));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    CK_BYTE_PTR
    Data = reinterpret_cast<CK_BYTE_PTR>(const_cast<char *>(data.data()));

    ret = P11LOADER_FUNC(C_Digest(loader->getSession(),
				  Data,
				  data.length(),
				  reinterpret_cast<unsigned char *>(dig),
				  &len));
    if (ret != CKR_OK)
    {
	std::cerr << "Error: " << loader->CKErr2Str(ret) << std::endl;
	return Result(Result::Failed);
    }

    digest->append(dig, len);

    return Result(Result::Succeeded);
}
