/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <fizz/server/FizzServer.h>
#include <fizz/server/FizzServerContext.h>

#include <folly/io/IOBufQueue.h>
#include <folly/io/async/DelayedDestruction.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>
#include <quic/state/StateData.h>

namespace quic {

// struct QuicConnectionStateBase;

/**
 * ServerHandshake abstracts details of the TLS 1.3 fizz crypto handshake. The
 * TLS handshake can be async, so ServerHandshake provides an API to deal with
 * the async handshake to work well with the re-entrancy requirements of the
 * QUIC state machine. The use of this is meant to be the following:
 *
 * handshake->doHandshake(newData); // This can throw an exception.
 * auto writeBytes = handshake->getWriteBytes();
 * auto hanshakeState = handshake->getHandshakeState();
 * writeBytesToSocket(writeBytes);
 *
 * If the handshake is async, then data will be returned async
 *
 * void onCryptoEventAvailable() noexcept {
 *   try {
 *     auto writeBytes = handshake->getWriteBytes();
 *     auto hanshakeState = handshake->getHandshakeState();
 *     writeBytesToSocket(writeBytes);
 *   } catch (const QuicTransportException& ex) {
 *     ....
 *   }
 *  }
 * }
 */

class ServerHandshake : public Handshake {
 public:
  class HandshakeCallback {
   public:
    virtual ~HandshakeCallback() = default;

    virtual void onCryptoEventAvailable() noexcept = 0;
  };

  /**
   * The 3 phases are as follows:
   * Handshake: We can only write crypto data with handshake keys
   * KeysDerived: Write crypto data with handshake keys and 1-rtt data with
   * 1-rtt keys.
   * Established: Write all data with 1-rtt keys.
   */
  enum class Phase { Handshake, KeysDerived, Established };

  explicit ServerHandshake(QuicConnectionStateBase* conn);

  /**
   * Starts accepting the TLS connection.
   */
  virtual void accept(
      std::shared_ptr<ServerTransportParametersExtension> transportParams);

  /**
   * Initialize the handshake with the executor and the callback.
   * The class will clone the context, so the same context will not be used
   * directly. To get the real context used, call getContext() after invoking
   * initialize.
   */
  virtual void initialize(
      folly::Executor* executor,
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator = nullptr);

  /**
   * Performs the handshake, after a handshake you should check whether or
   * not an event is available.
   */
  virtual void doHandshake(
      std::unique_ptr<folly::IOBuf> data,
      EncryptionLevel encryptionLevel);

  /**
   * Writes a session ticket on the connection.
   */
  virtual void writeNewSessionTicket(const AppToken& appToken);

  /**
   * Returns a reference to the CryptoFactory used internaly.
   */
  virtual const CryptoFactory& getCryptoFactory() const = 0;

  /**
   * An edge triggered API to get the handshakeReadCipher. Once you receive the
   * write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getHandshakeReadCipher();

  /**
   * An edge triggered API to get the oneRttWriteCipher. Once you receive the
   * write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getOneRttWriteCipher();

  /**
   * An edge triggered API to get the oneRttReadCipher. Once you receive the
   * read cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getOneRttReadCipher();

  /**
   * An edge triggered API to get the zeroRttReadCipher. Once you receive the
   * zero rtt read cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getZeroRttReadCipher();

  /**
   * An edge triggered API to get the one rtt read header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getOneRttReadHeaderCipher();

  /**
   * An edge triggered API to get the one rtt write header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getOneRttWriteHeaderCipher();

  /**
   * An edge triggered API to get the handshake rtt read header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getHandshakeReadHeaderCipher();

  /**
   * An edge triggered API to get the zero rtt header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getZeroRttReadHeaderCipher();

  /**
   * The application will not get any more callbacks from the handshake layer
   * after this method returns.
   */
  virtual void cancel();

  virtual Phase getPhase() const;

  /**
   * Returns the negotiated transport parameters from the client.
   */
  virtual folly::Optional<ClientTransportParameters> getClientTransportParams();

  /**
   * Returns whether all the events that the handshake needs are complete.
   */
  bool isHandshakeDone();

  virtual ~ServerHandshake() = default;

  void onError(std::pair<std::string, TransportErrorCode> error);

  void onWriteData(fizz::WriteToSocket& write);

  void onHandshakeDone();

  /**
   * Used to schedule actions to process which might be async.
   */
  void addProcessingActions(fizz::server::AsyncActions actions);

  /**
   * Start an async or synchronous action, once the async guard is acquired.
   */
  void startActions(fizz::server::AsyncActions actions);

  /**
   * Run the actions once they have been completed.
   */
  void processActions(
      fizz::server::ServerStateMachine::CompletedActions actions);

  /**
   * Process any pending events that might have been queued up because there
   * was an async action pending.
   */
  void processPendingEvents();

  virtual const std::shared_ptr<const folly::AsyncTransportCertificate>
  getPeerCertificate() const {
    return nullptr;
  }

 protected:
  Phase phase_{Phase::Handshake};

  enum class CipherKind {
    HandshakeRead,
    HandshakeWrite,
    OneRttRead,
    OneRttWrite,
    ZeroRttRead,
  };

  void computeCiphers(CipherKind kind, folly::ByteRange secret);

  QuicConnectionStateBase* conn_;
  folly::DelayedDestruction::DestructorGuard actionGuard_;
  folly::Executor* executor_;

  QuicCryptoState& cryptoState_;
  bool inProcessPendingEvents_{false};
  bool waitForData_{false};

  folly::IOBufQueue initialReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue handshakeReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue appDataReadBuf_{folly::IOBufQueue::cacheChainLength()};

  HandshakeCallback* callback_{nullptr};
  folly::Optional<std::pair<std::string, TransportErrorCode>> error_;

  std::unique_ptr<Aead> handshakeReadCipher_;
  std::unique_ptr<Aead> oneRttReadCipher_;
  std::unique_ptr<Aead> oneRttWriteCipher_;
  std::unique_ptr<Aead> zeroRttReadCipher_;

  std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> zeroRttReadHeaderCipher_;

  bool inHandshakeStack_{false};
  bool handshakeDone_{false};
  bool handshakeEventAvailable_{false};

  std::shared_ptr<ServerTransportParametersExtension> transportParams_;

 private:
  virtual void initializeImpl(
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator) = 0;

  virtual EncryptionLevel getReadRecordLayerEncryptionLevel() = 0;
  virtual void processSocketData(folly::IOBufQueue& queue) = 0;
  virtual std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(folly::ByteRange secret) = 0;

  virtual void processAccept() = 0;
  /*
   * Process a pending crypto event, if one was present. Returns if there was
   * a pending event.
   */
  virtual bool processPendingCryptoEvent() = 0;
  virtual void writeNewSessionTicketToCrypto(const AppToken& appToken) = 0;

  virtual void processCryptoActions(
      fizz::server::ServerStateMachine::CompletedActions actions) = 0;
}; // namespace quic

} // namespace quic
