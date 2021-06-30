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

} // namespace quic
