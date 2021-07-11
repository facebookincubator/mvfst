/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/fizz/server/handshake/FizzServerHandshake.h>

#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

#include <fizz/protocol/Protocol.h>
#include <fizz/server/State.h>

// This is necessary for the conversion between QuicServerConnectionState and
// QuicConnectionStateBase and can be removed once ServerHandshake accepts
// QuicServerConnectionState.
#include <quic/server/state/ServerStateMachine.h>

namespace fizz {
namespace server {
struct ResumptionState;
} // namespace server
} // namespace fizz

namespace {
class FailingAppTokenValidator : public fizz::server::AppTokenValidator {
  bool validate(const fizz::server::ResumptionState&) const override {
    return false;
  }
};
} // namespace

namespace quic {

FizzServerHandshake::FizzServerHandshake(
    QuicServerConnectionState* conn,
    std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext,
    std::unique_ptr<CryptoFactory> cryptoFactory)
    : ServerHandshake(conn), fizzContext_(std::move(fizzContext)) {
  CryptoFactory* cryptoFactoryPtr = cryptoFactory.release();
  auto* fizzCryptoFactoryPtr =
      dynamic_cast<FizzCryptoFactory*>(cryptoFactoryPtr);
  if (!fizzCryptoFactoryPtr) {
    cryptoFactory_ = std::make_unique<FizzCryptoFactory>();
  } else {
    cryptoFactory_.reset(fizzCryptoFactoryPtr);
  }
  CHECK(cryptoFactory_ && cryptoFactory_->getFizzFactory());
}

void FizzServerHandshake::initializeImpl(
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  auto context = std::make_shared<fizz::server::FizzServerContext>(
      *fizzContext_->getContext());
  context->setFactory(cryptoFactory_->getFizzFactory());
  context->setSupportedCiphers({{fizz::CipherSuite::TLS_AES_128_GCM_SHA256}});
  context->setVersionFallbackEnabled(false);
  // Since Draft-17, client won't sent EOED
  context->setOmitEarlyRecordLayer(true);
  state_.context() = std::move(context);
  callback_ = callback;

  if (validator) {
    state_.appTokenValidator() = std::move(validator);
  } else {
    state_.appTokenValidator() = std::make_unique<FailingAppTokenValidator>();
  }
}

const CryptoFactory& FizzServerHandshake::getCryptoFactory() const {
  return *cryptoFactory_;
}

const std::shared_ptr<const folly::AsyncTransportCertificate>
FizzServerHandshake::getPeerCertificate() const {
  return state_.clientCert();
}

const fizz::server::FizzServerContext* FizzServerHandshake::getContext() const {
  return state_.context();
}

const folly::Optional<std::string>&
FizzServerHandshake::getApplicationProtocol() const {
  return state_.alpn();
}

EncryptionLevel FizzServerHandshake::getReadRecordLayerEncryptionLevel() {
  return getEncryptionLevelFromFizz(
      state_.readRecordLayer()->getEncryptionLevel());
}

void FizzServerHandshake::processSocketData(folly::IOBufQueue& queue) {
  startActions(
      machine_.processSocketData(state_, queue, fizz::Aead::AeadOptions()));
}

std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
FizzServerHandshake::buildCiphers(folly::ByteRange secret) {
  auto aead = FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
      *state_.context()->getFactory(),
      *state_.keyScheduler(),
      *state_.cipher(),
      secret,
      kQuicKeyLabel,
      kQuicIVLabel));
  auto headerCipher = cryptoFactory_->makePacketNumberCipher(secret);

  return {std::move(aead), std::move(headerCipher)};
}

void FizzServerHandshake::processAccept() {
  addProcessingActions(machine_.processAccept(
      state_, executor_, state_.context(), transportParams_));
}

bool FizzServerHandshake::processPendingCryptoEvent() {
  if (pendingEvents_.empty()) {
    return false;
  }

  auto write = std::move(pendingEvents_.front());
  pendingEvents_.pop_front();
  startActions(machine_.processWriteNewSessionTicket(state_, std::move(write)));
  return true;
}

void FizzServerHandshake::writeNewSessionTicketToCrypto(
    const AppToken& appToken) {
  fizz::WriteNewSessionTicket writeNST;
  writeNST.appToken = encodeAppToken(appToken);
  pendingEvents_.push_back(std::move(writeNST));
}

class FizzServerHandshake::ActionMoveVisitor : public boost::static_visitor<> {
 public:
  explicit ActionMoveVisitor(FizzServerHandshake& server) : server_(server) {}

  void operator()(fizz::DeliverAppData&) {
    server_.onError(std::make_pair(
        "Unexpected data on crypto stream",
        TransportErrorCode::PROTOCOL_VIOLATION));
  }

  void operator()(fizz::WriteToSocket& write) {
    if (server_.isCancelled()) {
      // We've been canceled, just return. If we're canceled it's possible that
      // cryptoState_ has been deleted, so let's not refer to it.
      return;
    }

    for (auto& content : write.contents) {
      auto encryptionLevel =
          getEncryptionLevelFromFizz(content.encryptionLevel);
      if (content.contentType != fizz::ContentType::handshake) {
        continue;
      }
      server_.writeDataToStream(encryptionLevel, std::move(content.data));
    }

    server_.handshakeEventAvailable_ = true;
  }

  void operator()(fizz::server::ReportEarlyHandshakeSuccess&) {
    server_.phase_ = Phase::KeysDerived;
  }

  void operator()(fizz::server::ReportHandshakeSuccess&) {
    server_.handshakeDone_ = true;
    auto originalPhase = server_.phase_;
    // Fizz only reports handshake success when the server receives the full
    // client finished. At this point we can write any post handshake data and
    // crypto data with the 1-rtt keys.
    server_.phase_ = Phase::Established;
    if (originalPhase != Phase::Handshake) {
      // We already derived the zero rtt keys as well as the one rtt write
      // keys.
      server_.onHandshakeDone();
    }
  }

  void operator()(fizz::ReportError& err) {
    auto errMsg = err.error.what();
    if (errMsg.empty()) {
      errMsg = "Error during handshake";
    }

    auto fe = err.error.get_exception<fizz::FizzException>();

    if (fe && fe->getAlert()) {
      auto alertNum =
          static_cast<std::underlying_type<TransportErrorCode>::type>(
              fe->getAlert().value());
      alertNum += static_cast<std::underlying_type<TransportErrorCode>::type>(
          TransportErrorCode::CRYPTO_ERROR);
      server_.onError(std::make_pair(
          errMsg.toStdString(), static_cast<TransportErrorCode>(alertNum)));
    } else {
      server_.onError(std::make_pair(
          errMsg.toStdString(),
          static_cast<TransportErrorCode>(
              fizz::AlertDescription::internal_error)));
    }
  }

  void operator()(fizz::WaitForData&) {
    server_.waitForData_ = true;
  }

  void operator()(fizz::server::MutateState& mutator) {
    mutator(server_.state_);
  }

  void operator()(fizz::server::AttemptVersionFallback&) {
    CHECK(false) << "Fallback Unexpected";
  }

  void operator()(fizz::EndOfData&) {
    server_.onError(std::make_pair(
        "Unexpected close notify received",
        TransportErrorCode::INTERNAL_ERROR));
  }

  void operator()(fizz::SecretAvailable& secretAvailable) {
    switch (secretAvailable.secret.type.type()) {
      case fizz::SecretType::Type::EarlySecrets_E:
        switch (*secretAvailable.secret.type.asEarlySecrets()) {
          case fizz::EarlySecrets::ClientEarlyTraffic:
            server_.computeCiphers(
                CipherKind::ZeroRttRead,
                folly::range(secretAvailable.secret.secret));
            break;
          default:
            break;
        }
        break;
      case fizz::SecretType::Type::HandshakeSecrets_E:
        switch (*secretAvailable.secret.type.asHandshakeSecrets()) {
          case fizz::HandshakeSecrets::ClientHandshakeTraffic:
            server_.computeCiphers(
                CipherKind::HandshakeRead,
                folly::range(secretAvailable.secret.secret));
            break;
          case fizz::HandshakeSecrets::ServerHandshakeTraffic:
            server_.computeCiphers(
                CipherKind::HandshakeWrite,
                folly::range(secretAvailable.secret.secret));
            break;
        }
        break;
      case fizz::SecretType::Type::AppTrafficSecrets_E:
        switch (*secretAvailable.secret.type.asAppTrafficSecrets()) {
          case fizz::AppTrafficSecrets::ClientAppTraffic:
            server_.computeCiphers(
                CipherKind::OneRttRead,
                folly::range(secretAvailable.secret.secret));
            break;
          case fizz::AppTrafficSecrets::ServerAppTraffic:
            server_.computeCiphers(
                CipherKind::OneRttWrite,
                folly::range(secretAvailable.secret.secret));
            break;
        }
        break;
      case fizz::SecretType::Type::MasterSecrets_E:
        break;
    }
    server_.handshakeEventAvailable_ = true;
  }

 private:
  FizzServerHandshake& server_;
};

void FizzServerHandshake::processCryptoActions(
    fizz::server::ServerStateMachine::CompletedActions actions) {
  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    switch (action.type()) {
      case fizz::server::Action::Type::DeliverAppData_E:
        visitor(*action.asDeliverAppData());
        break;
      case fizz::server::Action::Type::WriteToSocket_E:
        visitor(*action.asWriteToSocket());
        break;
      case fizz::server::Action::Type::ReportHandshakeSuccess_E:
        visitor(*action.asReportHandshakeSuccess());
        break;
      case fizz::server::Action::Type::ReportEarlyHandshakeSuccess_E:
        visitor(*action.asReportEarlyHandshakeSuccess());
        break;
      case fizz::server::Action::Type::ReportError_E:
        visitor(*action.asReportError());
        break;
      case fizz::server::Action::Type::EndOfData_E:
        visitor(*action.asEndOfData());
        break;
      case fizz::server::Action::Type::MutateState_E:
        visitor(*action.asMutateState());
        break;
      case fizz::server::Action::Type::WaitForData_E:
        visitor(*action.asWaitForData());
        break;
      case fizz::server::Action::Type::AttemptVersionFallback_E:
        visitor(*action.asAttemptVersionFallback());
        break;
      case fizz::server::Action::Type::SecretAvailable_E:
        visitor(*action.asSecretAvailable());
        break;
    }
  }
}

} // namespace quic
