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

#include <cstdlib>

#include <QtCore/QDebug>
#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>
#include <QLoggingCategory>

#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"
#include "Crypto/lockcoderequest.h"
#include "cryptokiplugin.h"

#define bufferSize	(4 * 4096)
#define	P11LOADER_FUNC(func)	(loader)->GetFunctions()->func

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

using namespace Sailfish::Crypto;
namespace {
    const CK_BYTE STR_CRYPTO_PRO_A[] = {
	0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01
    };

    const CK_BYTE STR_CRYPTO_PRO_GOST3411[] = {
	0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01
    };

    //CK_BYTE STR_CRYPTO_PRO_GOST28147_A[] = {
	//0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01
    //};

    const int SIGNSIZE = 64;
} // anonymous namespace

Daemon::Plugins::CryptokiPlugin::CryptokiPlugin(QObject *parent)
    : QObject(parent), CryptoPlugin()
{

}

Daemon::Plugins::CryptokiPlugin::~CryptokiPlugin()
{

}

QVector<CryptoManager::Algorithm>
Daemon::Plugins::CryptokiPlugin::supportedAlgorithms() const
{
    QVector<CryptoManager::Algorithm> retn;
    retn.append(CryptoManager::AlgorithmGost);

    return retn;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::BlockMode> >
Daemon::Plugins::CryptokiPlugin::supportedBlockModes() const
{
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::BlockMode> > retn;
    retn.insert(CryptoManager::AlgorithmAes,
		QVector<CryptoManager::BlockMode>()
                       << CryptoManager::BlockModeCustom);

    return retn;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::EncryptionPadding> >
Daemon::Plugins::CryptokiPlugin::supportedEncryptionPaddings() const
{
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::EncryptionPadding> > retn;
    retn.insert(CryptoManager::AlgorithmAes, QVector<CryptoManager::EncryptionPadding>()
		<< CryptoManager::EncryptionPaddingNone);

    return retn;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::SignaturePadding> >
Daemon::Plugins::CryptokiPlugin::supportedSignaturePaddings() const
{
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::SignaturePadding> > retn;
    retn.insert(CryptoManager::AlgorithmGost,
                QVector<CryptoManager::SignaturePadding>()
		<< CryptoManager::SignaturePaddingNone);

    return retn;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::DigestFunction> >
Daemon::Plugins::CryptokiPlugin::supportedDigests() const
{
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::DigestFunction> > retn;
    retn.insert(CryptoManager::AlgorithmGost,
		QVector<CryptoManager::DigestFunction>()
		<< CryptoManager::DigestGost94
                << CryptoManager::DigestGost12_256
                << CryptoManager::DigestGost12_512);

    return retn;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::MessageAuthenticationCode> >
Daemon::Plugins::CryptokiPlugin::supportedMessageAuthenticationCodes() const
{
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::MessageAuthenticationCode> > retn;
    retn.insert(CryptoManager::AlgorithmGost,
		QVector<CryptoManager::MessageAuthenticationCode>()
		<< CryptoManager::MacHmac);

    return retn;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::KeyDerivationFunction> >
Daemon::Plugins::CryptokiPlugin::supportedKeyDerivationFunctions() const
{
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::KeyDerivationFunction> > retn;
    retn.insert(CryptoManager::AlgorithmGost,
		QVector<CryptoManager::KeyDerivationFunction>()
		<< CryptoManager::KdfCustom);

    return retn;
}

QMap<CryptoManager::Algorithm, CryptoManager::Operations>
Daemon::Plugins::CryptokiPlugin::supportedOperations() const
{
    QMap<CryptoManager::Algorithm, CryptoManager::Operations> retn;
    retn.insert(CryptoManager::AlgorithmGost,
		CryptoManager::OperationEncrypt |
		CryptoManager::OperationDecrypt |
		CryptoManager::OperationSign    |
		CryptoManager::OperationVerify);

    return retn;
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

    qWarning() << "DDD: seedRandomDataGenerator";

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

    qWarning() << "DDD: generateAndStoreKey";

    CK_BBOOL		bToken = TRUE;
    CK_BBOOL		bTrue = CK_TRUE;
    CK_BBOOL		bFalse = CK_FALSE;
    CK_MECHANISM	mech = {
	CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0
    };

    // Secret Key attributes
    // Note! All attributes can be and/or should be set up by &kpgParams for
    // example
    CK_ATTRIBUTE privKeyAttribs[] = {
        { CKA_TOKEN, (CK_VOID_PTR)&bToken, sizeof(bToken) }, // in token

	//CKM_GOSTR3410_KEY_PAIR_GEN,// Secret Key label
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

    CK_RV ret = P11LOADER_FUNC(C_GenerateKeyPair(
			       loader->getSession(),
			       &mech,
			       &pubKeyAttribs[0],
			       sizeof(pubKeyAttribs) /sizeof(CK_ATTRIBUTE),
			       &privKeyAttribs[0],
			       sizeof(privKeyAttribs)/sizeof(CK_ATTRIBUTE),
			       &hPublicKey, &hPrivateKey));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    const QByteArray PublicKeyData  =
	    QByteArray::number(static_cast<qulonglong>(hPublicKey));
    const QByteArray PrivateKeyData =
	    QByteArray::number(static_cast<qulonglong>(hPrivateKey));

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

    qWarning() << "DDD: storedKey";

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
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    ret = P11LOADER_FUNC(C_FindObjects(loader->getSession(),
					    &KeyHandle, 1, &KeyobjCount));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    ret = P11LOADER_FUNC(C_FindObjectsFinal(loader->getSession()));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    if (!KeyobjCount) {
	    qCCritical(lcLibLoader) << __func__ << "No key found";
	    return Result(Result::Failed);
    }

    const QByteArray KeyData  = QByteArray::number(static_cast<qulonglong>(KeyHandle));
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
	qWarning() << "DDD: getFullKey";
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
    //Q_UNUSED(randomData)
    unsigned char buf[2048] = {0};

	qWarning() << "DDD: generateRandomData";

    if (loader)
	    qWarning() << "loader != NULL";
    else {
	    qWarning() << "loader == NULL, create it! :((";
	    bool ret = unlock("12345678");
	    qWarning() << "ret = "  << ret;
    }

    qWarning() << "numberBytes:" << numberBytes
	    << "randomData size" << randomData->size();
    //numberBytes = 16;

    if (randomData == nullptr)
    {
	qWarning() << "randomData == nullptr";
	return Result(Result::Failed);
    }

    randomData->reserve(numberBytes);

    CK_RV ret = P11LOADER_FUNC(C_GenerateRandom(loader->getSession(),
			buf,
			//reinterpret_cast<unsigned char *>(randomData->data()),
			numberBytes));
    if (ret != CKR_OK)
    {
        qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
        return Result(Result::Failed);
    }

    for (unsigned int i = 0; i < numberBytes; i++)
	qWarning() << "c - " << buf[i];

    qWarning() << "generateRandomData exit DDD";
    //randomData->append(buf);

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
    Q_UNUSED(keyTemplate)
    Q_UNUSED(skdfParams)
    Q_UNUSED(kpgParams)


    qWarning() << "DDD: generateKey";
    CK_BBOOL	bTrue = CK_TRUE;

    //if (kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairUnknown)
    {

	CK_BBOOL	bToken = TRUE;
	CK_BBOOL	bFalse = CK_FALSE;
	CK_MECHANISM	mech = {
	    CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0
	};

	qWarning() << "DDD: NOT ! KeyPairUnknown";

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
		qCCritical(lcLibLoader) << "C_GenerateKeyPair Error: " << loader->CKErr2Str(ret);
		return Result(Result::Failed);
	}

	const QByteArray PublicKeyData  =
		QByteArray::number(static_cast<qulonglong>(hPublicKey));
	const QByteArray PrivateKeyData =
		QByteArray::number(static_cast<qulonglong>(hPrivateKey));

	key->setPublicKey(PublicKeyData);
	key->setPrivateKey(PrivateKeyData);
	key->setName("DDD kkkk");
	qWarning() << "DDD: End of key generarion";
    }
    /*else
    {
	CK_OBJECT_HANDLE SessionKeyHandle;
	CK_MECHANISM mech = {CKM_GOST28147_KEY_GEN, NULL, 0};
	CK_ATTRIBUTE KeyTemplate[] = {
		{CKA_GOST28147_PARAMS, STR_CRYPTO_PRO_GOST28147_A, sizeof(STR_CRYPTO_PRO_GOST28147_A)},
		{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
		{CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)}
	};

	qWarning() << "DDD: KeyPairUnknown !!!";

	const CK_RV ret = P11LOADER_FUNC(C_GenerateKey(loader->getSession(),
						       &mech,
						       KeyTemplate,
						       sizeof(KeyTemplate) / sizeof(CK_ATTRIBUTE),
						       &SessionKeyHandle));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_GenerateKey Error: " << loader->CKErr2Str(ret);
	    return Result(Result::Failed);
	}

	const QByteArray KeyData = QByteArray::number(static_cast<qulonglong>(SessionKeyHandle));
	key->setSecretKey(KeyData);
    }*/

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
    //if (digestFunction != CryptoManager::DigestFunction::DigestGost)
//	    return Result(Result::UnsupportedOperation,
//			 QLatin1String("The plugin supports only GOST"));

    char sign[SIGNSIZE];

    qWarning() << "DDD: sign";
    CK_ULONG nSignatureLength = sizeof(sign);

    //NOTE: One should choose a correct mechanism from in params
    CK_OBJECT_HANDLE	hPrivateKey = key.privateKey().toULong();
    CK_MECHANISM	mech;

    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;

    switch (digestFunction)
    {
    case CryptoManager::DigestFunction::DigestSingData:
	mech.mechanism = CKM_GOSTR3410_WITH_GOSTR3411; //sing data
	break;
    case CryptoManager::DigestFunction::DigestSingHash:
	mech.mechanism = CKM_GOSTR3410; //sign 32-bytes hash
	break;
    case CryptoManager::DigestFunction::DigestSingHMAC:
	mech.mechanism = CKM_GOSTR3410_WITH_GOSTR3411_2012_256;
	break;
    default:
	qWarning() << "Unknown mechanism:" << digestFunction;
	break;
    };

     qWarning() << "DDD: C_SignInit";
    CK_RV ret = P11LOADER_FUNC(C_SignInit(loader->getSession(),
					  &mech, hPrivateKey));
    CK_BYTE_PTR pSign = reinterpret_cast<CK_BYTE_PTR>(sign);

    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "C_SignInit Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    if (mech.mechanism == CKM_GOSTR3410_WITH_GOSTR3411)
    {
        int dataSize = data.length();
	unsigned char buf[bufferSize];

	while (dataSize > 0)
	{
	    int operationSize = dataSize >= bufferSize ? bufferSize : dataSize;
	    memcpy(buf, data.data(), operationSize);
	    qWarning() << "DDD: C_SignUpdate";
	    ret = P11LOADER_FUNC(C_SignUpdate(loader->getSession(), buf,
					      operationSize));
	    if (ret != CKR_OK)
	    {
	        qCCritical(lcLibLoader) << "C_SignUpdate Error: " << loader->CKErr2Str(ret);
		return Result(Result::Failed);
	    }
            dataSize -= operationSize;
	}

	qWarning() << "DDD: C_SignFinal";
	ret = P11LOADER_FUNC(C_SignFinal(loader->getSession(), pSign,
					 &nSignatureLength));

	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_SignFinal Error: " << loader->CKErr2Str(ret);
	    return Result(Result::Failed);
        }
    } else {
        CK_BYTE hash_data[32];
	memcpy(hash_data, data.data(), 32);
	qWarning() << "DDD: C_Sign";
	ret = P11LOADER_FUNC(C_Sign(loader->getSession(), hash_data,
				    sizeof(hash_data),
				    pSign, &nSignatureLength));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_Sign Error: " << loader->CKErr2Str(ret);
	    return Result(Result::Failed);
	}
    }

    signature->append(sign, nSignatureLength);
    qWarning() << "DDD Sing Succeeded";

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
	qWarning() << "DDD: verify";
//    if (digest != CryptoManager::DigestFunction::DigestGost)
//	    return Result(Result::UnsupportedOperation,
//			 QLatin1String("The plugin supports only GOST"));

    CK_OBJECT_HANDLE    hPublicKey = key.publicKey().toULong();
    CK_MECHANISM	mech;

    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;

    switch (digest)
    {
    case CryptoManager::DigestFunction::DigestSingData:
	mech.mechanism = CKM_GOSTR3410_WITH_GOSTR3411; //sing data
	break;
    case CryptoManager::DigestFunction::DigestSingHash:
	mech.mechanism = CKM_GOSTR3410; //sign 32-bytes hash
	break;
    case CryptoManager::DigestFunction::DigestSingHMAC:
	mech.mechanism = CKM_GOSTR3410_WITH_GOSTR3411_2012_256;
	break;
    default:
	qCWarning(lcLibLoader) << "Unknown mechanism:" << digest;
	break;
    };

    *verified = false;

    CK_RV ret = P11LOADER_FUNC(C_VerifyInit(loader->getSession(),
					    &mech, hPublicKey));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "C_VerifyInit Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    std::vector<unsigned char> sign(signature.length());
    memcpy(sign.data(), signature.data(), signature.length());

    if (mech.mechanism == CKM_GOSTR3410_WITH_GOSTR3411)
    {
        int dataSize = data.length();
	unsigned char buf[bufferSize];

        while (dataSize > 0) {
	    int operationSize = dataSize >= bufferSize ? bufferSize : dataSize;
	    memcpy(buf, data.data(), operationSize);
	    ret = P11LOADER_FUNC(C_VerifyUpdate(loader->getSession(), buf,
						operationSize));
	    if (ret != CKR_OK)
	    {
	        qCCritical(lcLibLoader) << "C_VerifyUpdate Error: " << loader->CKErr2Str(ret);
	        return Result(Result::Failed);
	    }
	    dataSize -= operationSize;
        }

        ret = P11LOADER_FUNC(C_VerifyFinal(loader->getSession(), sign.data(),
					   signature.length()));
        if (ret != CKR_OK)
        {
	    if (ret == CKR_SIGNATURE_INVALID)
	    {
	        return Result(Result::Succeeded);
	    }

	    qCCritical(lcLibLoader) << "C_VerifyFinal Error: " << loader->CKErr2Str(ret);
	    return Result(Result::Failed);
        }

    } else {
        CK_BYTE hash_data[32];
	memcpy(hash_data, data.data(), 32);
	ret = P11LOADER_FUNC(C_Verify(loader->getSession(), hash_data,
				      sizeof(hash_data),
				      sign.data(), signature.length()));
        if (ret != CKR_OK)
	{
            if (ret == CKR_SIGNATURE_INVALID)
	    {
                return Result(Result::Succeeded);
	    }
	    qCCritical(lcLibLoader) << "C_VerifyFinal Error: " << loader->CKErr2Str(ret);
	    return Result(Result::Failed);
	}
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
	qWarning() << "DDD: encrypt";
    long unsigned int iv_length = static_cast<long unsigned int>(iv.length());
    std::vector<char> iv_data(iv.length());
    memcpy(iv_data.data(), iv.data(), iv.length());

    CK_MECHANISM mech = {
	CKM_GOST28147, //can be configuired, may be by blockMode
	iv_data.data(),
	iv_length
    };

    CK_RV ret = P11LOADER_FUNC(C_EncryptInit(loader->getSession(), &mech,
					     key.secretKey().toULong()));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    std::vector<unsigned char> PlainText(data.length());
    memcpy(PlainText.data(), data.data(), data.length());

    CK_ULONG
    PlainTextLen = static_cast<CK_ULONG>(data.length());

    CK_BYTE_PTR
    EncData = reinterpret_cast<CK_BYTE_PTR>(encrypted->data());

    CK_ULONG EncDataLen;

    ret = P11LOADER_FUNC(C_Encrypt(loader->getSession(), PlainText.data(),
				   PlainTextLen, EncData, &EncDataLen));

    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
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
	qWarning() << "DDD: decrypt";
    long unsigned int iv_length = static_cast<long unsigned int>(iv.length());
    std::vector<char> iv_data(iv.length());
    memcpy(iv_data.data(), iv.data(), iv.length());

    CK_MECHANISM mech = {
	CKM_GOST28147, //Can be configuired I suppose, may be by blockMode
	iv_data.data(),
	iv_length
    };

    CK_RV ret = P11LOADER_FUNC(C_DecryptInit(loader->getSession(), &mech,
					     key.secretKey().toULong()));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    std::vector<unsigned char> EncData(data.length());
    memcpy(EncData.data(), data.data(), data.length());

    CK_ULONG
    EncDataLen = static_cast<CK_ULONG>(data.length());

    CK_BYTE_PTR
    PlainText = reinterpret_cast<CK_BYTE_PTR>(decrypted->data());
    CK_ULONG PlainTextLen;

    ret = P11LOADER_FUNC(C_Decrypt(loader->getSession(), EncData.data(),
				   EncDataLen, PlainText, &PlainTextLen));

    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << __func__ << "Error: " << loader->CKErr2Str(ret);
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
    char dig[SIGNSIZE] = {0};
    CK_MECHANISM mech;

    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;

    switch (digestFunction)
    {
	case CryptoManager::DigestFunction::DigestGost94:
	     mech.mechanism = CKM_GOSTR3411;
	     len = SIGNSIZE / 2;
	     break;
	case CryptoManager::DigestFunction::DigestGost12_256:
	     mech.mechanism = CKM_GOSTR3411_12_256;
	     len = SIGNSIZE / 2;
	     break;
	case CryptoManager::DigestFunction::DigestGost12_512:
	     mech.mechanism = CKM_GOSTR3411_12_512;
	     len = SIGNSIZE;
	     break;
	default:
	     qWarning() << "The Cryptoki plugin supports ONLY GOST";
	     return Result(Result::UnsupportedOperation,
			   QLatin1String("The Cryptoki plugin supports ONLY GOST"));
    }

    CK_RV ret = P11LOADER_FUNC(C_DigestInit(loader->getSession(), &mech));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "C_DigestInit Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    int dataSize = data.length();
    unsigned char buf[bufferSize];

    while (dataSize > 0) {
	int operationSize = dataSize >= bufferSize ? bufferSize : dataSize;
	memcpy(buf, data.data(), operationSize);
	ret = P11LOADER_FUNC(C_DigestUpdate(loader->getSession(), buf,
					    operationSize));
	if (ret != CKR_OK)
	{
	    qCCritical(lcLibLoader) << "C_DigestUpdate Error: " << loader->CKErr2Str(ret);
	    return Result(Result::Failed);
	}
	dataSize -= operationSize;
    }

    ret = P11LOADER_FUNC(C_DigestFinal(loader->getSession(),
				       reinterpret_cast<unsigned char *>(dig),
				       &len));
    if (ret != CKR_OK)
    {
	qCCritical(lcLibLoader) << "C_DigestFinal Error: " << loader->CKErr2Str(ret);
	return Result(Result::Failed);
    }

    for (int j = 0; j < SIGNSIZE; j++)
	    fprintf(stderr, "%.2x", dig[j]);

    digest->append(dig, len);

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::initialiseCipherSession(
    quint64 clientId,
    const QByteArray &iv,
    const Key &key, // or keyreference, i.e. Key(keyName)
    CryptoManager::Operation operation,
    CryptoManager::BlockMode blockMode,
    CryptoManager::EncryptionPadding encryptionPadding,
    CryptoManager::SignaturePadding signaturePadding,
    CryptoManager::DigestFunction digestFunction,
    quint32 *cipherSessionToken,
    QByteArray *generatedIV)
{
	Q_UNUSED(clientId)
	Q_UNUSED(iv)
	Q_UNUSED(operation)
	Q_UNUSED(blockMode)
	Q_UNUSED(encryptionPadding)
	Q_UNUSED(signaturePadding)
	Q_UNUSED(digestFunction)
	Q_UNUSED(cipherSessionToken)
	Q_UNUSED(generatedIV)
    Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Result(Result::EmptySecretKey,
		      QLatin1String("Cannot create a cipher session with empty secret key"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::updateCipherSessionAuthentication(
    quint64 clientId,
    const QByteArray &authenticationData,
    quint32 cipherSessionToken)
{
	Q_UNUSED(clientId)
	Q_UNUSED(authenticationData)
	Q_UNUSED(cipherSessionToken)
    //if (!m_cipherSessions.contains(clientId)
//	|| !m_cipherSessions[clientId].contains(cipherSessionToken)) {
  //      return Result(Result::CryptoPluginCipherSessionError,
//		      QLatin1String("Unknown cipher session token provided"));
  //  }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::updateCipherSession(
    quint64 clientId,
    const QByteArray &data,
    quint32 cipherSessionToken,
    QByteArray *generatedData)
{
    Q_UNUSED(clientId)
    Q_UNUSED(data)
    Q_UNUSED(cipherSessionToken)
    Q_UNUSED(generatedData)
    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::CryptokiPlugin::finaliseCipherSession(
    quint64 clientId,
    const QByteArray &data,
    quint32 cipherSessionToken,
    QByteArray *generatedData,
    bool *verified)
{
    Q_UNUSED(clientId)
    Q_UNUSED(data)
    Q_UNUSED(cipherSessionToken)
    Q_UNUSED(generatedData)
    Q_UNUSED(verified)
    return Result(Result::Succeeded);
}

bool
Daemon::Plugins::CryptokiPlugin::supportsLocking() const
{
    return true;
}

bool
Daemon::Plugins::CryptokiPlugin::isLocked() const
{
    return !loader->IsInitialized();
}

bool
Daemon::Plugins::CryptokiPlugin::lock()
{
    return loader->lock();
}

bool
Daemon::Plugins::CryptokiPlugin::unlock(const QByteArray &lockCode)
{
    qWarning() << "DDD: unlock";
    loader.reset(new LibLoader);

    return loader->unlock(lockCode);
}

bool
Daemon::Plugins::CryptokiPlugin::setLockCode(const QByteArray &oldLockCode,
					     const QByteArray &newLockCode)
{
    return loader->setLockCode(oldLockCode, newLockCode);
}
