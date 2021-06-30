/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/server/handshake/ServerHandshake.h>

#include <fizz/server/ServerProtocol.h>

namespace quic {

class FizzServerQuicHandshakeContext;
struct QuicServerConnectionState;

class FizzServerHandshake : public ServerHandshake {
 public:
  FizzServerHandshake(
      QuicServerConnectionState* conn,
      std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext,
      std::unique_ptr<CryptoFactory> cryptoFactory);

  const CryptoFactory& getCryptoFactory() const override;

  /**
   * Retuns the clent's certificate.
   */
  const std::shared_ptr<const folly::AsyncTransportCertificate>
  getPeerCertificate() const override;

  /**
   * Retuns the negotiated ALPN from the handshake.
   */
  const folly::Optional<std::string>& getApplicationProtocol() const override;

  /**
   * Returns the context used by the ServerHandshake.
   */
  const fizz::server::FizzServerContext* getContext() const;

 private:
  void initializeImpl(
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator) override;

  EncryptionLevel getReadRecordLayerEncryptionLevel() override;
  void processSocketData(folly::IOBufQueue& queue) override;
  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(folly::ByteRange secret) override;

  void processAccept() override;
  bool processPendingCryptoEvent() override;
  void writeNewSessionTicketToCrypto(const AppToken& appToken) override;

  using PendingEvent = fizz::WriteNewSessionTicket;
  std::deque<PendingEvent> pendingEvents_;

  std::unique_ptr<FizzCryptoFactory> cryptoFactory_;

  std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext_;
};

} // namespace quic
