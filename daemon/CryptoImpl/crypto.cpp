/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "crypto_p.h"
#include "cryptorequestprocessor_p.h"
#include "logging_p.h"

#include "Crypto/serialisation_p.h"
#include "Crypto/cryptodaemonconnection_p.h"

#include "Crypto/key.h"
#include "Crypto/result.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QString>
#include <QtCore/QVector>
#include <QtCore/QByteArray>

using namespace Sailfish::Crypto;

Daemon::ApiImpl::CryptoDBusObject::CryptoDBusObject(
        Daemon::ApiImpl::CryptoRequestQueue *parent)
    : QObject(parent)
    , m_requestQueue(parent)
{
}


void Daemon::ApiImpl::CryptoDBusObject::getPluginInfo(
        const QDBusMessage &message,
        Result &result,
        QVector<Sailfish::Crypto::PluginInfo> &cryptoPlugins,
        QVector<Sailfish::Crypto::PluginInfo> &storagePlugins)
{
    Q_UNUSED(cryptoPlugins);   // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(storagePlugins);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Daemon::ApiImpl::GetPluginInfoRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateRandomData(
        quint64 numberBytes,
        const QString &csprngEngineName,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &randomData)
{
    Q_UNUSED(randomData);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<quint64>(numberBytes);
    inParams << QVariant::fromValue<QString>(csprngEngineName);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateRandomDataRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::seedRandomDataGenerator(
        const QByteArray &seedData,
        double entropyEstimate,
        const QString &csprngEngineName,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(seedData);
    inParams << QVariant::fromValue<double>(entropyEstimate);
    inParams << QVariant::fromValue<QString>(csprngEngineName);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SeedRandomDataGeneratorRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateInitializationVector(
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &generatedIV)
{
    Q_UNUSED(generatedIV);  // outparam

    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Crypto::CryptoManager::Algorithm>(algorithm);
    inParams << QVariant::fromValue<Sailfish::Crypto::CryptoManager::BlockMode>(blockMode);
    inParams << QVariant::fromValue<int>(keySize);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateInitializationVectorRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateKey(
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key>(keyTemplate);
    inParams << QVariant::fromValue<KeyPairGenerationParameters>(kpgParams);
    inParams << QVariant::fromValue<KeyDerivationParameters>(skdfParams);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateStoredKey(
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key>(keyTemplate);
    inParams << QVariant::fromValue<KeyPairGenerationParameters>(kpgParams);
    inParams << QVariant::fromValue<KeyDerivationParameters>(skdfParams);
    inParams << QVariant::fromValue<InteractionParameters>(uiParams);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::importKey(
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        Key &importedKey)
{
    Q_UNUSED(importedKey);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<InteractionParameters>(uiParams);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ImportKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::importStoredKey(
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        Key &importedKey)
{
    Q_UNUSED(importedKey);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<InteractionParameters>(uiParams);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ImportStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
        const QDBusMessage &message,
        Result &result,
        Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key::Identifier>(identifier);
    inParams << QVariant::fromValue<Key::Components>(keyComponents);
    m_requestQueue->handleRequest(Daemon::ApiImpl::StoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::deleteStoredKey(
        const Key::Identifier &identifier,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key::Identifier>(identifier);
    m_requestQueue->handleRequest(Daemon::ApiImpl::DeleteStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::storedKeyIdentifiers(
        const QString &storagePluginName,
        const QDBusMessage &message,
        Result &result,
        QVector<Key::Identifier> &identifiers)
{
    Q_UNUSED(identifiers);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << storagePluginName;
    m_requestQueue->handleRequest(Daemon::ApiImpl::StoredKeyIdentifiersRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::calculateDigest(
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &digest)
{
    Q_UNUSED(digest);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<CryptoManager::SignaturePadding>(padding);
    inParams << QVariant::fromValue<CryptoManager::DigestFunction>(digestFunction);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::CalculateDigestRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::sign(
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digest,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &signature)
{
    Q_UNUSED(signature);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<CryptoManager::SignaturePadding>(padding);
    inParams << QVariant::fromValue<CryptoManager::DigestFunction>(digest);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SignRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digest,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        bool &verified)
{
    Q_UNUSED(verified);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(signature);
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<CryptoManager::SignaturePadding>(padding);
    inParams << QVariant::fromValue<CryptoManager::DigestFunction>(digest);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::VerifyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &encrypted,
        QByteArray &authenticationTag)
{
    // outparams, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encrypted);
    Q_UNUSED(authenticationTag);

    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QByteArray>(iv);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<CryptoManager::BlockMode>(blockMode);
    inParams << QVariant::fromValue<CryptoManager::EncryptionPadding>(padding);
    inParams << QVariant::fromValue<QByteArray>(authenticationData);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::EncryptRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &decrypted,
        bool &verified)
{
    // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(decrypted);
    Q_UNUSED(verified);

    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QByteArray>(iv);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<CryptoManager::BlockMode>(blockMode);
    inParams << QVariant::fromValue<CryptoManager::EncryptionPadding>(padding);
    inParams << QVariant::fromValue<QByteArray>(authenticationData);
    inParams << QVariant::fromValue<QByteArray>(authenticationTag);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::DecryptRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::initialiseCipherSession(
        const QByteArray &initialisationVector,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digest,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        quint32 &cipherSessionToken)
{
    Q_UNUSED(cipherSessionToken);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(initialisationVector);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<CryptoManager::Operation>(operation);
    inParams << QVariant::fromValue<CryptoManager::BlockMode>(blockMode);
    inParams << QVariant::fromValue<CryptoManager::EncryptionPadding>(encryptionPadding);
    inParams << QVariant::fromValue<CryptoManager::SignaturePadding>(signaturePadding);
    inParams << QVariant::fromValue<CryptoManager::DigestFunction>(digest);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::InitialiseCipherSessionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::updateCipherSessionAuthentication(
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(authenticationData);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<quint32>(cipherSessionToken);
    m_requestQueue->handleRequest(Daemon::ApiImpl::UpdateCipherSessionAuthenticationRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::updateCipherSession(
        const QByteArray &data,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &generatedData)
{
    Q_UNUSED(generatedData);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<quint32>(cipherSessionToken);
    m_requestQueue->handleRequest(Daemon::ApiImpl::UpdateCipherSessionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::finaliseCipherSession(
        const QByteArray &data,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &generatedData,
        bool &verified)
{
    Q_UNUSED(generatedData);  // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(verified);       // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QVariantMap>(customParameters);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<quint32>(cipherSessionToken);
    m_requestQueue->handleRequest(Daemon::ApiImpl::FinaliseCipherSessionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::modifyLockCode(
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
             << QVariant::fromValue<QString>(lockCodeTarget)
             << QVariant::fromValue<InteractionParameters>(interactionParameters);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ModifyLockCodeRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::provideLockCode(
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
             << QVariant::fromValue<QString>(lockCodeTarget)
             << QVariant::fromValue<InteractionParameters>(interactionParameters);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ProvideLockCodeRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::forgetLockCode(
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
             << QVariant::fromValue<QString>(lockCodeTarget)
             << QVariant::fromValue<InteractionParameters>(interactionParameters);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ForgetLockCodeRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

//-----------------------------------

Daemon::ApiImpl::CryptoRequestQueue::CryptoRequestQueue(
        Sailfish::Secrets::Daemon::Controller *parent,
        Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
        bool autotestMode)
    : Sailfish::Secrets::Daemon::ApiImpl::RequestQueue(
          QLatin1String("/Sailfish/Crypto"),
          QLatin1String("org.sailfishos.crypto"),
          parent,
          autotestMode)
    , m_requestProcessor(Q_NULLPTR)
    , m_controller(parent)
{
    CryptoDaemonConnection::registerDBusTypes();

    m_cryptoThreadPool = QSharedPointer<QThreadPool>::create();
    m_cryptoThreadPool->setMaxThreadCount(1);
    m_cryptoThreadPool->setExpiryTimeout(-1);
    m_requestProcessor = new Daemon::ApiImpl::RequestProcessor(secrets, autotestMode, this);

    setDBusObject(new Daemon::ApiImpl::CryptoDBusObject(this));
    qCDebug(lcSailfishCryptoDaemon) << "Crypto: initialisation succeeded, awaiting client connections.";
}

Daemon::ApiImpl::CryptoRequestQueue::~CryptoRequestQueue()
{
}

Sailfish::Secrets::Daemon::Controller*
Daemon::ApiImpl::CryptoRequestQueue::controller()
{
    return m_controller;
}

QWeakPointer<QThreadPool> Daemon::ApiImpl::CryptoRequestQueue::cryptoThreadPool()
{
    return m_cryptoThreadPool.toWeakRef();
}

QMap<QString, Sailfish::Crypto::CryptoPlugin*>
Daemon::ApiImpl::CryptoRequestQueue::plugins() const
{
    return m_requestProcessor->plugins();
}

bool Daemon::ApiImpl::CryptoRequestQueue::lockPlugin(
        const QString &pluginName)
{
    return m_requestProcessor->lockPlugin(pluginName);
}

bool Daemon::ApiImpl::CryptoRequestQueue::unlockPlugin(
        const QString &pluginName,
        const QByteArray &lockCode)
{
    return m_requestProcessor->unlockPlugin(pluginName, lockCode);
}

bool Daemon::ApiImpl::CryptoRequestQueue::setLockCodePlugin(
        const QString &pluginName,
        const QByteArray &oldCode,
        const QByteArray &newCode)
{
    return m_requestProcessor->setLockCodePlugin(pluginName, oldCode, newCode);
}

QString Daemon::ApiImpl::CryptoRequestQueue::requestTypeToString(int type) const
{
    switch (type) {
        case InvalidRequest:                   return QLatin1String("InvalidRequest");
        case GetPluginInfoRequest:             return QLatin1String("GetPluginInfoRequest");
        case GenerateRandomDataRequest:        return QLatin1String("GenerateRandomDataRequest");
        case SeedRandomDataGeneratorRequest:   return QLatin1String("SeedRandomDataGeneratorRequest");
        case GenerateInitializationVectorRequest: return QLatin1String("GenerateInitializationVectorRequest");
        case GenerateKeyRequest:               return QLatin1String("GenerateKeyRequest");
        case GenerateStoredKeyRequest:         return QLatin1String("GenerateStoredKeyRequest");
        case ImportKeyRequest:                 return QLatin1String("ImportKeyRequest");
        case ImportStoredKeyRequest:           return QLatin1String("ImportStoredKeyRequest");
        case StoredKeyRequest:                 return QLatin1String("StoredKeyRequest");
        case DeleteStoredKeyRequest:           return QLatin1String("DeleteStoredKeyRequest");
        case StoredKeyIdentifiersRequest:      return QLatin1String("StoredKeyIdentifiersRequest");
        case CalculateDigestRequest:           return QLatin1String("CalculateDigestRequest");
        case SignRequest:                      return QLatin1String("SignRequest");
        case VerifyRequest:                    return QLatin1String("VerifyRequest");
        case EncryptRequest:                   return QLatin1String("EncryptRequest");
        case DecryptRequest:                   return QLatin1String("DecryptRequest");
        case InitialiseCipherSessionRequest:   return QLatin1String("InitialiseCipherSessionRequest");
        case UpdateCipherSessionAuthenticationRequest: return QLatin1String("UpdateCipherSessionAuthenticationRequest");
        case UpdateCipherSessionRequest:       return QLatin1String("UpdateCipherSessionRequest");
        case FinaliseCipherSessionRequest:     return QLatin1String("FinaliseCipherSessionRequest");
        case ModifyLockCodeRequest:            return QLatin1String("ModifyLockCodeRequest");
        case ProvideLockCodeRequest:           return QLatin1String("ProvideLockCodeRequest");
        case ForgetLockCodeRequest:            return QLatin1String("ForgetLockCodeRequest");
        default: break;
    }
    return QLatin1String("Unknown Crypto Request!");
}

void Daemon::ApiImpl::CryptoRequestQueue::handlePendingRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GetPluginInfoRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<PluginInfo> cryptoPlugins;
            QVector<PluginInfo> storagePlugins;
            Result result = m_requestProcessor->getPluginInfo(
                        request->remotePid,
                        request->requestId,
                        &cryptoPlugins,
                        &storagePlugins);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<PluginInfo> >(cryptoPlugins)
                                                                        << QVariant::fromValue<QVector<PluginInfo> >(storagePlugins));
                *completed = true;
            }
            break;
        }
        case GenerateRandomDataRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateRandomDataRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray randomData;
            quint64 numberBytes = request->inParams.size() ? request->inParams.takeFirst().value<quint64>() : 0;
            QString csprngEngineName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->generateRandomData(
                        request->remotePid,
                        request->requestId,
                        numberBytes,
                        csprngEngineName,
                        customParameters,
                        cryptosystemProviderName,
                        &randomData);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(randomData));
                *completed = true;
            }
            break;
        }
        case SeedRandomDataGeneratorRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling SeedRandomDataGeneratorRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray seedData = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            double entropyEstimate = request->inParams.size() ? request->inParams.takeFirst().value<double>() : 1.0;
            QString csprngEngineName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->seedRandomDataGenerator(
                        request->remotePid,
                        request->requestId,
                        seedData,
                        entropyEstimate,
                        csprngEngineName,
                        customParameters,
                        cryptosystemProviderName);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case GenerateInitializationVectorRequest:
        {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateInitializationVectorRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray generatedIV;
            CryptoManager::Algorithm algorithm = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::Algorithm>() : CryptoManager::AlgorithmUnknown;
            CryptoManager::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::BlockMode>() : CryptoManager::BlockModeUnknown;
            int keySize = request->inParams.size() ? request->inParams.takeFirst().value<int>() : -1;
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->generateInitializationVector(
                        request->remotePid,
                        request->requestId,
                        algorithm,
                        blockMode,
                        keySize,
                        customParameters,
                        cryptosystemProviderName,
                        &generatedIV);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedIV));
                *completed = true;
            }
            break;
        }
        case GenerateKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key key;
            Key templateKey = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key>()
                    : Key();
            KeyPairGenerationParameters kpgParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<KeyPairGenerationParameters>()
                    : KeyPairGenerationParameters();
            KeyDerivationParameters skdfParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<KeyDerivationParameters>()
                    : KeyDerivationParameters();
            QVariantMap customParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<QVariantMap>()
                    : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = m_requestProcessor->generateKey(
                        request->remotePid,
                        request->requestId,
                        templateKey,
                        kpgParams,
                        skdfParams,
                        customParameters,
                        cryptosystemProviderName,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case GenerateStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key key;
            Key templateKey = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key>()
                    : Key();
            KeyPairGenerationParameters kpgParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<KeyPairGenerationParameters>()
                    : KeyPairGenerationParameters();
            KeyDerivationParameters skdfParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<KeyDerivationParameters>()
                    : KeyDerivationParameters();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            QVariantMap customParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<QVariantMap>()
                    : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = m_requestProcessor->generateStoredKey(
                        request->remotePid,
                        request->requestId,
                        templateKey,
                        kpgParams,
                        skdfParams,
                        uiParams,
                        customParameters,
                        cryptosystemProviderName,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case ImportKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key importedKey;
            Key key = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key>()
                    : Key();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            QVariantMap customParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<QVariantMap>()
                    : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = m_requestProcessor->importKey(
                        request->remotePid,
                        request->requestId,
                        key,
                        uiParams,
                        customParameters,
                        cryptosystemProviderName,
                        QByteArray(),
                        &importedKey);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(importedKey));
                *completed = true;
            }
            break;
        }
        case ImportStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key importedKey;
            Key key = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key>()
                    : Key();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            QVariantMap customParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<QVariantMap>()
                    : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = m_requestProcessor->importStoredKey(
                        request->remotePid,
                        request->requestId,
                        key,
                        uiParams,
                        customParameters,
                        cryptosystemProviderName,
                        &importedKey);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(importedKey));
                *completed = true;
            }
            break;
        }
        case StoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling StoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key key;
            Key::Identifier ident = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key::Identifier>()
                    : Key::Identifier();
            Key::Components components = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key::Components>()
                    : (Key::MetaData | Key::PublicKeyData);
            Result result = m_requestProcessor->storedKey(
                        request->remotePid,
                        request->requestId,
                        ident,
                        components,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case DeleteStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling DeleteStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key::Identifier identifier = request->inParams.size()
                                                         ? request->inParams.takeFirst().value<Key::Identifier>()
                                                         : Key::Identifier();
            Result result = m_requestProcessor->deleteStoredKey(
                        request->remotePid,
                        request->requestId,
                        identifier);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling StoredKeyIdentifiersRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString storagePluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            QVector<Key::Identifier> identifiers;
            Result result = m_requestProcessor->storedKeyIdentifiers(
                        request->remotePid,
                        request->requestId,
                        storagePluginName,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<Key::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case CalculateDigestRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling CalculateDigestRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray digest;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            CryptoManager::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::SignaturePadding>() : CryptoManager::SignaturePaddingUnknown;
            CryptoManager::DigestFunction digestFunction = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::DigestFunction>() : CryptoManager::DigestUnknown;
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->calculateDigest(
                        request->remotePid,
                        request->requestId,
                        data,
                        padding,
                        digestFunction,
                        customParameters,
                        cryptosystemProviderName,
                        &digest);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(digest));
                *completed = true;
            }
            break;
        }
        case SignRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling SignRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray signature;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            CryptoManager::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::SignaturePadding>() : CryptoManager::SignaturePaddingUnknown;
            CryptoManager::DigestFunction digest = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::DigestFunction>() : CryptoManager::DigestUnknown;
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->sign(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        padding,
                        digest,
                        customParameters,
                        cryptosystemProviderName,
                        &signature);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(signature));
                *completed = true;
            }
            break;
        }
        case VerifyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling VerifyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            bool verified = false;
            QByteArray signature = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            CryptoManager::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::SignaturePadding>() : CryptoManager::SignaturePaddingUnknown;
            CryptoManager::DigestFunction digest = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::DigestFunction>() : CryptoManager::DigestUnknown;
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->verify(
                        request->remotePid,
                        request->requestId,
                        signature,
                        data,
                        key,
                        padding,
                        digest,
                        customParameters,
                        cryptosystemProviderName,
                        &verified);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case EncryptRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling EncryptRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray encrypted;
            QByteArray authenticationTag;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QByteArray iv = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            CryptoManager::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::BlockMode>() : CryptoManager::BlockModeUnknown;
            CryptoManager::EncryptionPadding padding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::EncryptionPadding>() : CryptoManager::EncryptionPaddingUnknown;
            QByteArray authenticationData = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->encrypt(
                          request->remotePid,
                          request->requestId,
                          data,
                          iv,
                          key,
                          blockMode,
                          padding,
                          authenticationData,
                          customParameters,
                          cryptosystemProviderName,
                          &encrypted,
                          &authenticationTag);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(encrypted)
                                                                        << QVariant::fromValue<QByteArray>(authenticationTag));
                *completed = true;
            }
            break;
        }
        case DecryptRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling DecryptRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray decrypted;
            bool verified = false;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QByteArray iv = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            CryptoManager::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::BlockMode>() : CryptoManager::BlockModeUnknown;
            CryptoManager::EncryptionPadding padding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::EncryptionPadding>() : CryptoManager::EncryptionPaddingUnknown;
            QByteArray authenticationData = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QByteArray authenticationTag = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->decrypt(
                        request->remotePid,
                        request->requestId,
                        data,
                        iv,
                        key,
                        blockMode,
                        padding,
                        authenticationData,
                        authenticationTag,
                        customParameters,
                        cryptosystemProviderName,
                        &decrypted,
                        &verified);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(decrypted)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case InitialiseCipherSessionRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling InitialiseCipherSessionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            quint32 cipherSessionToken = 0;
            QByteArray iv = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            CryptoManager::Operation operation = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::Operation>() : CryptoManager::OperationUnknown;
            CryptoManager::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::BlockMode>() : CryptoManager::BlockModeUnknown;
            CryptoManager::EncryptionPadding encryptionPadding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::EncryptionPadding>() : CryptoManager::EncryptionPaddingUnknown;
            CryptoManager::SignaturePadding signaturePadding = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::SignaturePadding>() : CryptoManager::SignaturePaddingUnknown;
            CryptoManager::DigestFunction digest = request->inParams.size() ? request->inParams.takeFirst().value<CryptoManager::DigestFunction>() : CryptoManager::DigestUnknown;
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->initialiseCipherSession(
                        request->remotePid,
                        request->requestId,
                        iv,
                        key,
                        operation,
                        blockMode,
                        encryptionPadding,
                        signaturePadding,
                        digest,
                        customParameters,
                        cryptosystemProviderName,
                        &cipherSessionToken);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<quint32>(cipherSessionToken));
                *completed = true;
            }
            break;
        }
        case UpdateCipherSessionAuthenticationRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling UpdateCipherSessionAuthenticationRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray authenticationData = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            quint32 cipherSessionToken = request->inParams.size() ? request->inParams.takeFirst().value<quint32>() : 0;
            Result result = m_requestProcessor->updateCipherSessionAuthentication(
                        request->remotePid,
                        request->requestId,
                        authenticationData,
                        customParameters,
                        cryptosystemProviderName,
                        cipherSessionToken);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case UpdateCipherSessionRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling UpdateCipherSessionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray generatedData;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            quint32 cipherSessionToken = request->inParams.size() ? request->inParams.takeFirst().value<quint32>() : 0;
            Result result = m_requestProcessor->updateCipherSession(
                        request->remotePid,
                        request->requestId,
                        data,
                        customParameters,
                        cryptosystemProviderName,
                        cipherSessionToken,
                        &generatedData);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedData));
                *completed = true;
            }
            break;
        }
        case FinaliseCipherSessionRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling FinaliseCipherSessionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray generatedData;
            bool verified = false;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QVariantMap customParameters = request->inParams.size() ? request->inParams.takeFirst().value<QVariantMap>() : QVariantMap();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            quint32 cipherSessionToken = request->inParams.size() ? request->inParams.takeFirst().value<quint32>() : 0;
            Result result = m_requestProcessor->finaliseCipherSession(
                        request->remotePid,
                        request->requestId,
                        data,
                        customParameters,
                        cryptosystemProviderName,
                        cipherSessionToken,
                        &generatedData,
                        &verified);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedData)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case ModifyLockCodeRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling ModifyLockCodeRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            LockCodeRequest::LockCodeTargetType lockCodeTargetType = request->inParams.size()
                    ? request->inParams.takeFirst().value<LockCodeRequest::LockCodeTargetType>()
                    : LockCodeRequest::ExtensionPlugin;
            QString lockCodeTarget = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters interactionParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            Result result = m_requestProcessor->modifyLockCode(
                        request->remotePid,
                        request->requestId,
                        lockCodeTargetType,
                        lockCodeTarget,
                        interactionParameters);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case ProvideLockCodeRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling ProvideLockCodeRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            LockCodeRequest::LockCodeTargetType lockCodeTargetType = request->inParams.size()
                    ? request->inParams.takeFirst().value<LockCodeRequest::LockCodeTargetType>()
                    : LockCodeRequest::ExtensionPlugin;
            QString lockCodeTarget = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters interactionParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            Result result = m_requestProcessor->provideLockCode(
                        request->remotePid,
                        request->requestId,
                        lockCodeTargetType,
                        lockCodeTarget,
                        interactionParameters);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case ForgetLockCodeRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling ForgetLockCodeRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            LockCodeRequest::LockCodeTargetType lockCodeTargetType = request->inParams.size()
                    ? request->inParams.takeFirst().value<LockCodeRequest::LockCodeTargetType>()
                    : LockCodeRequest::ExtensionPlugin;
            QString lockCodeTarget = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters interactionParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            Result result = m_requestProcessor->forgetLockCode(
                        request->remotePid,
                        request->requestId,
                        lockCodeTargetType,
                        lockCodeTarget,
                        interactionParameters);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishCryptoDaemon) << "Cannot handle request:" << request->requestId
                                              << "with invalid type:" << requestTypeToString(request->type);
            *completed = false;
            break;
        }
    }
}

void Daemon::ApiImpl::CryptoRequestQueue::handleFinishedRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetPluginInfoRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GetPluginInfoRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<PluginInfo> cryptoPlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<PluginInfo> >()
                        : QVector<PluginInfo>();
                QVector<PluginInfo> storagePlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<PluginInfo> >()
                        : QVector<PluginInfo>();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<PluginInfo> >(cryptoPlugins)
                                                                        << QVariant::fromValue<QVector<PluginInfo> >(storagePlugins));
                *completed = true;
            }
            break;
        }
        case GenerateRandomDataRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateRandomDataRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateRandomDataRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray randomData = request->outParams.size() ? request->outParams.takeFirst().value<QByteArray>() : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(randomData));
                *completed = true;
            }
            break;
        }
        case SeedRandomDataGeneratorRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SeedRandomDataGeneratorRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "SeedRandomDataGeneratorRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case GenerateInitializationVectorRequest:
        {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateInitializationVectorRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateInitializationVectorRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray generatedIV = request->outParams.size() ? request->outParams.takeFirst().value<QByteArray>() : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedIV));
                *completed = true;
            }
            break;
        }
        case GenerateKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case GenerateStoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateStoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case ImportKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ImportKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ImportKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case ImportStoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ImportStoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ImportStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case StoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of StoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "StoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case DeleteStoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteStoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "DeleteStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of StoredKeyIdentifiersRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "StoredKeyIdentifiersRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<Key::Identifier> identifiers = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<Key::Identifier> >()
                        : QVector<Key::Identifier>();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<Key::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case CalculateDigestRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SignRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "CalculateDigestRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray digest = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(digest));
                *completed = true;
            }
            break;
        }
        case SignRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SignRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "SignRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray signature = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(signature));
                *completed = true;
            }
            break;
        }
        case VerifyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of VerifyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "VerifyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                bool verified = request->outParams.size()
                        ? request->outParams.takeFirst().toBool()
                        : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case EncryptRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of EncryptRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "EncryptRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray encrypted = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                QByteArray authenticationTag = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(encrypted)
                                                                        << QVariant::fromValue<QByteArray>(authenticationTag));
                *completed = true;
            }
            break;
        }
        case DecryptRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DecryptRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "DecryptRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray decrypted = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                bool verified = request->outParams.size()
                        ? request->outParams.takeFirst().toBool()
                        : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(decrypted)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case InitialiseCipherSessionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of InitialiseCipherSessionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "InitialiseCipherSessionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                quint32 cipherSessionToken = request->outParams.size()
                        ? request->outParams.takeFirst().value<quint32>()
                        : 0;
                QByteArray generatedIV = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<quint32>(cipherSessionToken)
                                                                        << QVariant::fromValue<QByteArray>(generatedIV));
                *completed = true;
            }
            break;
        }
        case UpdateCipherSessionAuthenticationRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of UpdateCipherSessionAuthenticationRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "UpdateCipherSessionAuthenticationRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case UpdateCipherSessionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of UpdateCipherSessionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "UpdateCipherSessionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray generatedData = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedData));
                *completed = true;
            }
            break;
        }
        case FinaliseCipherSessionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of FinaliseCipherSessionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "FinaliseCipherSessionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray generatedData = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                bool verified = request->outParams.size()
                        ? request->outParams.takeFirst().toBool()
                        : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedData)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case ModifyLockCodeRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ModifyLockCodeRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ModifyLockCodeRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case ProvideLockCodeRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ProvideLockCodeRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ProvideLockCodeRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case ForgetLockCodeRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ForgetLockCodeRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ForgetLockCodeRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishCryptoDaemon) << "Cannot handle synchronous request:" << request->requestId << "with type:" << requestTypeToString(request->type) << "in an asynchronous fashion";
            *completed = false;
            break;
        }
    }
}
