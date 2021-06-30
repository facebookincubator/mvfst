/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/ServerHandshake.h>

#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {
ServerHandshake::ServerHandshake(QuicConnectionStateBase* conn)
    : conn_(conn), actionGuard_(nullptr), cryptoState_(*conn->cryptoState) {}

void ServerHandshake::accept(
    std::shared_ptr<ServerTransportParametersExtension> transportParams) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  transportParams_ = std::move(transportParams);
  inHandshakeStack_ = true;
  processAccept();
}

void ServerHandshake::initialize(
    folly::Executor* executor,
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  executor_ = executor;
  initializeImpl(callback, std::move(validator));
}

void ServerHandshake::doHandshake(
    std::unique_ptr<folly::IOBuf> data,
    EncryptionLevel encryptionLevel) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  waitForData_ = false;
  switch (encryptionLevel) {
    case EncryptionLevel::Initial:
      initialReadBuf_.append(std::move(data));
      break;
    case EncryptionLevel::Handshake:
      handshakeReadBuf_.append(std::move(data));
      break;
    case EncryptionLevel::EarlyData:
    case EncryptionLevel::AppData:
      appDataReadBuf_.append(std::move(data));
      break;
    default:
      LOG(FATAL) << "Unhandled EncryptionLevel";
  }
  processPendingEvents();
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
}

void ServerHandshake::writeNewSessionTicket(const AppToken& appToken) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  writeNewSessionTicketToCrypto(appToken);
  processPendingEvents();
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
}

std::unique_ptr<Aead> ServerHandshake::getHandshakeReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(handshakeReadCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getOneRttWriteCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttWriteCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getOneRttReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttReadCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getZeroRttReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(zeroRttReadCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getOneRttReadHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getOneRttWriteHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getHandshakeReadHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(handshakeReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getZeroRttReadHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(zeroRttReadHeaderCipher_);
}

/**
 * The application will not get any more callbacks from the handshake layer
 * after this method returns.
 */
void ServerHandshake::cancel() {
  callback_ = nullptr;
}

ServerHandshake::Phase ServerHandshake::getPhase() const {
  return phase_;
}

folly::Optional<ClientTransportParameters>
ServerHandshake::getClientTransportParams() {
  return transportParams_->getClientTransportParams();
}

bool ServerHandshake::isHandshakeDone() {
  return handshakeDone_;
}

void ServerHandshake::onError(
    std::pair<std::string, TransportErrorCode> error) {
  VLOG(10) << "ServerHandshake error " << error.first;
  error_ = error;
  handshakeEventAvailable_ = true;
}

void ServerHandshake::onWriteData(fizz::WriteToSocket& write) {
  if (!callback_) {
    // We've been canceled, just return. If we're canceled it's possible that
    // cryptoState_ has been deleted, so let's not refer to it.
    return;
  }
  for (auto& content : write.contents) {
    auto encryptionLevel = getEncryptionLevelFromFizz(content.encryptionLevel);
    CHECK(encryptionLevel != EncryptionLevel::EarlyData)
        << "Server cannot write early data";
    if (content.contentType != fizz::ContentType::handshake) {
      continue;
    }
    auto cryptoStream = getCryptoStream(cryptoState_, encryptionLevel);
    writeDataToQuicStream(*cryptoStream, std::move(content.data));
  }
  handshakeEventAvailable_ = true;
}

void ServerHandshake::onHandshakeDone() {
  handshakeEventAvailable_ = true;
}

void ServerHandshake::addProcessingActions(fizz::server::AsyncActions actions) {
  if (actionGuard_) {
    onError(std::make_pair(
        "Processing action while pending", TransportErrorCode::INTERNAL_ERROR));
    return;
  }
  actionGuard_ = folly::DelayedDestruction::DestructorGuard(conn_);
  startActions(std::move(actions));
}

void ServerHandshake::startActions(fizz::server::AsyncActions actions) {
  folly::variant_match(
      actions,
      [this](folly::Future<fizz::server::Actions>& futureActions) {
        std::move(futureActions).then(&ServerHandshake::processActions, this);
      },
      [this](fizz::server::Actions& immediateActions) {
        this->processActions(std::move(immediateActions));
      });
}

void ServerHandshake::processPendingEvents() {
  if (inProcessPendingEvents_) {
    return;
  }

  folly::DelayedDestruction::DestructorGuard dg(conn_);
  inProcessPendingEvents_ = true;
  SCOPE_EXIT {
    inProcessPendingEvents_ = false;
  };

  while (!actionGuard_ && !error_) {
    actionGuard_ = folly::DelayedDestruction::DestructorGuard(conn_);
    if (!waitForData_) {
      switch (getReadRecordLayerEncryptionLevel()) {
        case EncryptionLevel::Initial:
          processSocketData(initialReadBuf_);
          break;
        case EncryptionLevel::Handshake:
          processSocketData(handshakeReadBuf_);
          break;
        case EncryptionLevel::EarlyData:
        case EncryptionLevel::AppData:
          // TODO: Get rid of appDataReadBuf_ once we do not need EndOfEarlyData
          // any more.
          processSocketData(appDataReadBuf_);
          break;
        default:
          LOG(FATAL) << "Unhandled EncryptionLevel";
      }
    } else if (!processPendingCryptoEvent()) {
      actionGuard_ = folly::DelayedDestruction::DestructorGuard(nullptr);
      return;
    }
  }
}

void ServerHandshake::processActions(
    fizz::server::ServerStateMachine::CompletedActions actions) {
  // This extra DestructorGuard is needed due to the gap between clearing
  // actionGuard_ and potentially processing another action.
  folly::DelayedDestruction::DestructorGuard dg(conn_);

  processCryptoActions(std::move(actions));

  actionGuard_ = folly::DelayedDestruction::DestructorGuard(nullptr);
  if (callback_ && !inHandshakeStack_ && handshakeEventAvailable_) {
    callback_->onCryptoEventAvailable();
  }
  handshakeEventAvailable_ = false;
  processPendingEvents();
}

void ServerHandshake::computeCiphers(CipherKind kind, folly::ByteRange secret) {
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  std::tie(aead, headerCipher) = buildCiphers(secret);
  switch (kind) {
    case CipherKind::HandshakeRead:
      handshakeReadCipher_ = std::move(aead);
      handshakeReadHeaderCipher_ = std::move(headerCipher);
      break;
    case CipherKind::HandshakeWrite:
      conn_->handshakeWriteCipher = std::move(aead);
      conn_->handshakeWriteHeaderCipher = std::move(headerCipher);
      break;
    case CipherKind::OneRttRead:
      oneRttReadCipher_ = std::move(aead);
      oneRttReadHeaderCipher_ = std::move(headerCipher);
      break;
    case CipherKind::OneRttWrite:
      oneRttWriteCipher_ = std::move(aead);
      oneRttWriteHeaderCipher_ = std::move(headerCipher);
      break;
    case CipherKind::ZeroRttRead:
      zeroRttReadCipher_ = std::move(aead);
      zeroRttReadHeaderCipher_ = std::move(headerCipher);
      break;
    default:
      folly::assume_unreachable();
  }
  handshakeEventAvailable_ = true;
}

} // namespace quic
