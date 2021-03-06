/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 *
 * This plugin is aimed to provide a high level interface to interact
 * with Cryto Token USB devices supported PKSC#11 standard.
 *
 * Copyright (C) 2017 Open Mobile Platform LLC.
 * Contact: Denis Semakin <d.semakin@omprussia.ru>
 * All rights reserved.
 */

#ifndef SAILFISHCRYPTO_PLUGIN_CRYPTOKI_H
#define SAILFISHCRYPTO_PLUGIN_CRYPTOKI_H

#include <memory>

#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QCryptographicHash>
#include <QtCore/QMap>

//#include "Crypto/extensionplugins.h"
#include "libloader.h"
#include "tk26.h"

class CipherSessionData;
class QTimer;

namespace Sailfish {

namespace Crypto {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT CryptokiPlugin : public QObject, public Sailfish::Crypto::CryptoPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin)

public:
    CryptokiPlugin(QObject *parent = Q_NULLPTR);
    ~CryptokiPlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHCRYPTO_TESTPLUGIN
        return QLatin1String("org.sailfishos.crypto.plugin.crypto.token.test");
#else
        return QLatin1String("org.sailfishos.crypto.plugin.crypto.token");
#endif
    }

    bool canStoreKeys() const Q_DECL_OVERRIDE { return false; }

    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE { return Sailfish::Crypto::CryptoPlugin::SoftwareEncryption; }

    QVector<Sailfish::Crypto::CryptoManager::Algorithm> supportedAlgorithms() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > supportedBlockModes() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > supportedEncryptionPaddings() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > supportedSignaturePaddings() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > supportedDigests() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::MessageAuthenticationCode> > supportedMessageAuthenticationCodes() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::KeyDerivationFunction> > supportedKeyDerivationFunctions() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> supportedOperations() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            QByteArray *randomData) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result seedRandomDataGenerator(
            quint64 callerIdent,
            const QString &csprngEngineName,
            const QByteArray &seedData,
            double entropyEstimate) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            bool *validated) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            Sailfish::Crypto::Key *keyMetadata) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKeyIdentifiers(
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digest,
            QByteArray *signature) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result verify(
	    const QByteArray &signature,
	    const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            bool *verified) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            QByteArray *encrypted) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            QByteArray *decrypted) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result calculateDigest(
	    const QByteArray &data,
	    Sailfish::Crypto::CryptoManager::SignaturePadding padding,
	    Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
	    QByteArray *digest) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result initialiseCipherSession(
            quint64 clientId,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digest,
            quint32 *cipherSessionToken,
            QByteArray *generatedIV) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result updateCipherSessionAuthentication(
            quint64 clientId,
            const QByteArray &authenticationData,
            quint32 cipherSessionToken) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result updateCipherSession(
            quint64 clientId,
            const QByteArray &data,
            quint32 cipherSessionToken,
            QByteArray *generatedData) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result finaliseCipherSession(
            quint64 clientId,
            const QByteArray &data,
            quint32 cipherSessionToken,
            QByteArray *generatedData,
            bool *verified) Q_DECL_OVERRIDE;

    bool supportsLocking() const Q_DECL_OVERRIDE;
    bool isLocked() const Q_DECL_OVERRIDE;
    bool lock() Q_DECL_OVERRIDE;
    bool unlock(const QByteArray &lockCode) Q_DECL_OVERRIDE;
    bool setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode) Q_DECL_OVERRIDE;

private:
    Sailfish::Crypto::Key getFullKey(const Sailfish::Crypto::Key &key);
    QMap<quint64, QMap<quint32, CipherSessionData*> > m_cipherSessions; // clientId to token to data
    struct CipherSessionLookup {
        CipherSessionData *csd = 0;
        quint32 sessionToken = 0;
        quint64 clientId = 0;
    };
    QMap<QTimer *, CipherSessionLookup> m_cipherSessionTimeouts;
    std::unique_ptr<LibLoader> loader;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Crypto

} // namespace Sailfish

#endif // SAILFISHCRYPTO_PLUGIN_CRYPTOKI_H
