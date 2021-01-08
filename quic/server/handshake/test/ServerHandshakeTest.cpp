/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <condition_variable>
#include <mutex>

#include <fizz/client/test/Mocks.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/clock/test/Mocks.h>
#include <fizz/protocol/test/Mocks.h>
#include <fizz/server/test/Mocks.h>

#include <folly/io/async/SSLContext.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/ssl/Init.h>

#include <quic/QuicConstants.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientExtensions.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/fizz/server/handshake/FizzServerHandshake.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/state/StateData.h>

using namespace std;
using namespace folly;
using namespace testing;

static constexpr StringPiece kTestHostname = "www.facebook.com";

namespace quic {
namespace test {
class MockServerHandshakeCallback : public ServerHandshake::HandshakeCallback {
 public:
  ~MockServerHandshakeCallback() override = default;

  MOCK_METHOD(void, onCryptoEventAvailable, (), (noexcept));
};

struct TestingServerConnectionState : public QuicServerConnectionState {
  explicit TestingServerConnectionState(
      std::shared_ptr<FizzServerQuicHandshakeContext> context)
      : QuicServerConnectionState(std::move(context)) {}

  uint32_t getDestructorGuardCount() const {
    return folly::DelayedDestruction::getDestructorGuardCount();
  }
};

class ServerHandshakeTest : public Test {
 public:
  ~ServerHandshakeTest() override = default;

  virtual void setupClientAndServerContext() {}

  QuicVersion getVersion() {
    return QuicVersion::QUIC_DRAFT;
  }

  virtual void initialize() {
    handshake->initialize(&evb, &serverCallback);
  }

  void SetUp() override {
    folly::ssl::init();
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setOmitEarlyRecordLayer(true);
    clientCtx->setFactory(std::make_shared<QuicFizzFactory>());
    clientCtx->setClock(std::make_shared<fizz::test::MockClock>());
    serverCtx = quic::test::createServerCtx();
    setupClientAndServerContext();
    auto fizzServerContext = FizzServerQuicHandshakeContext::Builder()
                                 .setFizzServerContext(serverCtx)
                                 .build();
    conn.reset(new TestingServerConnectionState(fizzServerContext));
    cryptoState = conn->cryptoState.get();
    handshake = conn->serverHandshakeLayer;
    hostname = kTestHostname.str();
    verifier = std::make_shared<fizz::test::MockCertificateVerifier>();

    uint64_t initialMaxData = kDefaultConnectionWindowSize;
    uint64_t initialMaxStreamDataBidiLocal = kDefaultStreamWindowSize;
    uint64_t initialMaxStreamDataBidiRemote = kDefaultStreamWindowSize;
    uint64_t initialMaxStreamDataUni = kDefaultStreamWindowSize;
    uint64_t initialMaxStreamsBidi = kDefaultMaxStreamsBidirectional;
    uint64_t initialMaxStreamsUni = kDefaultMaxStreamsUnidirectional;
    auto clientExtensions =
        std::make_shared<ClientTransportParametersExtension>(
            getVersion(),
            initialMaxData,
            initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni,
            initialMaxStreamsBidi,
            initialMaxStreamsUni,
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            kDefaultActiveConnectionIdLimit,
            ConnectionId(std::vector<uint8_t>()));
    fizzClient.reset(
        new fizz::client::
            FizzClient<ServerHandshakeTest, fizz::client::ClientStateMachine>(
                clientState, clientReadBuffer, *this, dg.get()));
    std::vector<QuicVersion> supportedVersions = {getVersion()};
    auto params = std::make_shared<ServerTransportParametersExtension>(
        getVersion(),
        initialMaxData,
        initialMaxStreamDataBidiLocal,
        initialMaxStreamDataBidiRemote,
        initialMaxStreamDataUni,
        initialMaxStreamsBidi,
        initialMaxStreamsUni,
        kDefaultIdleTimeout,
        kDefaultAckDelayExponent,
        kDefaultUDPSendPacketLen,
        kDefaultPartialReliability,
        generateStatelessResetToken(),
        ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
        ConnectionId(std::vector<uint8_t>()));
    initialize();
    handshake->accept(params);

    ON_CALL(serverCallback, onCryptoEventAvailable())
        .WillByDefault(Invoke([this]() {
          VLOG(1) << "onCryptoEventAvailable";
          processCryptoEvents();
        }));
    auto cachedPsk = clientCtx->getPsk(hostname);
    fizzClient->connect(
        clientCtx,
        verifier,
        hostname,
        cachedPsk,
        folly::Optional<std::vector<fizz::ech::ECHConfig>>(folly::none),
        std::make_shared<FizzClientExtensions>(clientExtensions));
  }

  void processCryptoEvents() {
    try {
      setHandshakeState();
      waitForData = false;
      auto writableBytes = getHandshakeWriteBytes();
      while (writableBytes && !writableBytes->empty() && !waitForData) {
        VLOG(1) << "server->client bytes="
                << writableBytes->computeChainDataLength();
        clientReadBuffer.append(std::move(writableBytes));
        if (!clientReadBuffer.empty()) {
          fizzClient->newTransportData();
        }
        if (!waitForData) {
          writableBytes = getHandshakeWriteBytes();
        }
      }
    } catch (const QuicTransportException& e) {
      VLOG(1) << "server exception " << e.what();
      ex = std::make_exception_ptr(e);
    }
    if (!inRoundScope_ && !handshakeCv.ready()) {
      VLOG(1) << "Posting handshake cv";
      handshakeCv.post();
    }
  }

  void clientServerRound() {
    SCOPE_EXIT {
      inRoundScope_ = false;
    };
    inRoundScope_ = true;
    evb.loop();
    try {
      for (auto& clientWrite : clientWrites) {
        for (auto& content : clientWrite.contents) {
          auto encryptionLevel =
              getEncryptionLevelFromFizz(content.encryptionLevel);
          handshake->doHandshake(std::move(content.data), encryptionLevel);
        }
      }
      processCryptoEvents();
    } catch (const QuicTransportException&) {
      ex = std::current_exception();
    }
    evb.loopIgnoreKeepAlive();
  }

  void serverClientRound() {
    SCOPE_EXIT {
      inRoundScope_ = false;
    };
    inRoundScope_ = true;
    evb.loop();
    waitForData = false;
    auto writableBytes = getHandshakeWriteBytes();
    while (writableBytes && !writableBytes->empty() && !waitForData) {
      VLOG(1) << "server->client bytes="
              << writableBytes->computeChainDataLength();
      clientReadBuffer.append(std::move(writableBytes));
      if (!clientReadBuffer.empty()) {
        fizzClient->newTransportData();
      }
      if (!waitForData) {
        writableBytes = getHandshakeWriteBytes();
      }
    }
    evb.loop();
  }

  void setHandshakeState() {
    auto oneRttWriteCipherTmp = handshake->getOneRttWriteCipher();
    auto oneRttReadCipherTmp = handshake->getOneRttReadCipher();
    auto zeroRttReadCipherTmp = handshake->getZeroRttReadCipher();
    auto handshakeWriteCipherTmp = std::move(conn->handshakeWriteCipher);
    auto handshakeReadCipherTmp = handshake->getHandshakeReadCipher();
    if (oneRttWriteCipherTmp) {
      oneRttWriteCipher = std::move(oneRttWriteCipherTmp);
    }
    if (oneRttReadCipherTmp) {
      oneRttReadCipher = std::move(oneRttReadCipherTmp);
    }
    if (zeroRttReadCipherTmp) {
      zeroRttReadCipher = std::move(zeroRttReadCipherTmp);
    }
    if (handshakeReadCipherTmp) {
      handshakeReadCipher = std::move(handshakeReadCipherTmp);
    }
    if (handshakeWriteCipherTmp) {
      handshakeWriteCipher = std::move(handshakeWriteCipherTmp);
    }
  }

  void expectOneRttReadCipher(bool expected) {
    EXPECT_EQ(oneRttReadCipher.get() != nullptr, expected);
  }

  void expectOneRttWriteCipher(bool expected) {
    EXPECT_EQ(oneRttWriteCipher.get() != nullptr, expected);
  }

  void expectOneRttCipher(bool expected) {
    expectOneRttWriteCipher(expected);
    expectOneRttReadCipher(expected);

    if (expected) {
      EXPECT_EQ(zeroRttReadCipher.get(), nullptr);
    } else {
      EXPECT_EQ(zeroRttReadCipher.get(), nullptr);
    }
  }

  void expectZeroRttCipher(bool expected, bool oneRttRead) {
    CHECK(expected || !oneRttRead) << "invalid condition supplied";
    EXPECT_NE(oneRttWriteCipher.get(), nullptr);
    if (expected) {
      if (oneRttRead) {
        EXPECT_NE(oneRttReadCipher.get(), nullptr);
      } else {
        EXPECT_EQ(oneRttReadCipher.get(), nullptr);
      }
      EXPECT_NE(zeroRttReadCipher.get(), nullptr);
    } else {
      EXPECT_EQ(oneRttReadCipher.get(), nullptr);
      EXPECT_EQ(zeroRttReadCipher.get(), nullptr);
    }
  }

  Buf getHandshakeWriteBytes() {
    auto buf = folly::IOBuf::create(0);
    switch (clientState.readRecordLayer()->getEncryptionLevel()) {
      case fizz::EncryptionLevel::Plaintext:
        if (!cryptoState->initialStream.writeBuffer.empty()) {
          buf->prependChain(cryptoState->initialStream.writeBuffer.move());
        }
        break;
      case fizz::EncryptionLevel::Handshake:
      case fizz::EncryptionLevel::EarlyData:
        if (!cryptoState->handshakeStream.writeBuffer.empty()) {
          buf->prependChain(cryptoState->handshakeStream.writeBuffer.move());
        }
        break;
      case fizz::EncryptionLevel::AppTraffic:
        if (!cryptoState->oneRttStream.writeBuffer.empty()) {
          buf->prependChain(cryptoState->oneRttStream.writeBuffer.move());
        }
    }
    return buf;
  }

  void operator()(fizz::DeliverAppData&) {}
  void operator()(fizz::WriteToSocket& write) {
    clientWrites.push_back(std::move(write));
  }
  void operator()(fizz::client::ReportEarlyHandshakeSuccess&) {
    earlyHandshakeSuccess = true;
  }
  void operator()(fizz::client::ReportHandshakeSuccess&) {
    handshakeSuccess = true;
  }
  void operator()(fizz::client::ReportEarlyWriteFailed&) {
    earlyWriteFailed = true;
  }
  void operator()(fizz::ReportError&) {
    error = true;
  }
  void operator()(fizz::WaitForData&) {
    waitForData = true;
    fizzClient->waitForData();
  }
  void operator()(fizz::client::MutateState& mutator) {
    mutator(clientState);
  }
  void operator()(fizz::client::NewCachedPsk& newCachedPsk) {
    clientCtx->putPsk(hostname, std::move(newCachedPsk.psk));
  }
  void operator()(fizz::SecretAvailable&) {}

  void operator()(fizz::EndOfData&) {}

  class DelayedHolder : public folly::DelayedDestruction {};

  std::unique_ptr<DelayedHolder, folly::DelayedDestruction::Destructor> dg;

  folly::EventBase evb;
  std::unique_ptr<
      TestingServerConnectionState,
      folly::DelayedDestruction::Destructor>
      conn{nullptr};
  ServerHandshake* handshake;
  QuicCryptoState* cryptoState;

  fizz::client::State clientState;
  std::unique_ptr<fizz::client::FizzClient<
      ServerHandshakeTest,
      fizz::client::ClientStateMachine>>
      fizzClient;
  folly::IOBufQueue clientReadBuffer{folly::IOBufQueue::cacheChainLength()};
  bool earlyHandshakeSuccess{false};
  bool handshakeSuccess{false};
  bool earlyWriteFailed{false};
  bool error{false};

  std::vector<fizz::WriteToSocket> clientWrites;
  MockServerHandshakeCallback serverCallback;

  std::unique_ptr<Aead> oneRttWriteCipher;
  std::unique_ptr<Aead> oneRttReadCipher;
  std::unique_ptr<Aead> zeroRttReadCipher;
  std::unique_ptr<Aead> handshakeWriteCipher;
  std::unique_ptr<Aead> handshakeReadCipher;

  std::exception_ptr ex;
  std::string hostname;
  std::shared_ptr<fizz::test::MockCertificateVerifier> verifier;
  std::shared_ptr<fizz::client::FizzClientContext> clientCtx;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;
  folly::Baton<> handshakeCv;
  bool inRoundScope_{false};
  bool waitForData{false};
};

TEST_F(ServerHandshakeTest, TestHandshakeSuccess) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  if (ex) {
    std::rethrow_exception(ex);
  }
  expectOneRttCipher(true);
  EXPECT_EQ(handshake->getApplicationProtocol(), folly::none);
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ServerHandshakeTest, TestHandshakeSuccessIgnoreNonHandshake) {
  fizz::WriteToSocket write;
  fizz::TLSContent content;
  content.contentType = fizz::ContentType::alert;
  content.data = folly::IOBuf::copyBuffer(folly::unhexlify("01000000"));
  content.encryptionLevel = fizz::EncryptionLevel::Plaintext;
  write.contents.push_back(std::move(content));
  clientWrites.push_back(std::move(write));
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  if (ex) {
    std::rethrow_exception(ex);
  }
  expectOneRttCipher(true);
  EXPECT_EQ(handshake->getApplicationProtocol(), folly::none);
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ServerHandshakeTest, TestMalformedHandshakeMessage) {
  fizz::WriteToSocket write;
  fizz::TLSContent content;
  content.contentType = fizz::ContentType::handshake;
  content.data = folly::IOBuf::copyBuffer(folly::unhexlify("01000000"));
  content.encryptionLevel = fizz::EncryptionLevel::Plaintext;
  write.contents.push_back(std::move(content));
  clientWrites.clear();
  clientWrites.push_back(std::move(write));
  clientServerRound();

  EXPECT_TRUE(ex);
}

class AsyncRejectingTicketCipher : public fizz::server::TicketCipher {
 public:
  ~AsyncRejectingTicketCipher() override = default;

  folly::Future<folly::Optional<
      std::pair<std::unique_ptr<folly::IOBuf>, std::chrono::seconds>>>
  encrypt(fizz::server::ResumptionState) const override {
    if (!encryptAsync_) {
      return std::make_pair(IOBuf::create(0), 2s);
    } else {
      encryptAsync_ = false;
      return std::move(encryptFuture_).thenValue([](auto&&) {
        VLOG(1) << "got ticket async";
        return std::make_pair(IOBuf::create(0), 2s);
      });
    }
  }

  void setDecryptAsync(bool async, folly::Future<folly::Unit> future) {
    decryptAsync_ = async;
    decryptFuture_ = std::move(future);
  }

  void setEncryptAsync(bool async, folly::Future<folly::Unit> future) {
    encryptAsync_ = async;
    encryptFuture_ = std::move(future);
  }

  void setDecryptError(bool error) {
    error_ = error;
  }

  folly::Future<
      std::pair<fizz::PskType, folly::Optional<fizz::server::ResumptionState>>>
  decrypt(std::unique_ptr<folly::IOBuf>) const override {
    if (!decryptAsync_) {
      if (error_) {
        throw std::runtime_error("test decrypt error");
      }
      return std::make_pair(fizz::PskType::Rejected, folly::none);
    } else {
      decryptAsync_ = false;
      return std::move(decryptFuture_).thenValue([&](auto&&) {
        VLOG(1) << "triggered reject";
        if (error_) {
          throw std::runtime_error("test decrypt error");
        }
        return std::make_pair(fizz::PskType::Rejected, folly::none);
      });
    }
  }

 private:
  mutable folly::Future<folly::Unit> decryptFuture_;
  mutable folly::Future<folly::Unit> encryptFuture_;
  mutable bool decryptAsync_{true};
  mutable bool encryptAsync_{false};
  bool error_{false};
};

class ServerHandshakeWriteNSTTest : public ServerHandshakeTest {
 public:
  void setupClientAndServerContext() override {
    serverCtx->setSendNewSessionTicket(false);
    ticketCipher_ = std::make_shared<fizz::server::test::MockTicketCipher>();
    ticketCipher_->setDefaults();
    serverCtx->setTicketCipher(ticketCipher_);
    cache_ = std::make_shared<fizz::client::BasicPskCache>();
    clientCtx->setPskCache(cache_);
    clientCtx->setSupportedAlpns({"h1q-fb"});
    serverCtx->setSupportedAlpns({"h1q-fb", "hq"});
  }

 protected:
  std::shared_ptr<fizz::client::BasicPskCache> cache_;
  std::shared_ptr<fizz::server::test::MockTicketCipher> ticketCipher_;
};

TEST_F(ServerHandshakeWriteNSTTest, TestWriteNST) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);

  AppToken appToken;

  EXPECT_FALSE(cache_->getPsk(kTestHostname.str()));
  EXPECT_CALL(*ticketCipher_, _encrypt(_))
      .WillOnce(Invoke([&appToken](fizz::server::ResumptionState& resState) {
        EXPECT_TRUE(
            folly::IOBufEqualTo()(resState.appToken, encodeAppToken(appToken)));
        return std::make_pair(folly::IOBuf::copyBuffer("appToken"), 100s);
      }));
  handshake->writeNewSessionTicket(appToken);
  processCryptoEvents();
  evb.loop();
  EXPECT_TRUE(cache_->getPsk(kTestHostname.str()));
}

class ServerHandshakePskTest : public ServerHandshakeTest {
 public:
  ~ServerHandshakePskTest() override = default;

  void SetUp() override {
    cache = std::make_shared<fizz::client::BasicPskCache>();
    psk.psk = std::string("psk");
    psk.secret = std::string("secret");
    psk.type = fizz::PskType::Resumption;
    psk.version = fizz::ProtocolVersion::tls_1_3;
    psk.cipher = fizz::CipherSuite::TLS_AES_128_GCM_SHA256;
    psk.group = fizz::NamedGroup::x25519;
    psk.serverCert = std::make_shared<fizz::test::MockCert>();
    psk.alpn = std::string("h1q-fb");
    psk.ticketAgeAdd = 1;
    psk.ticketIssueTime = std::chrono::system_clock::time_point();
    psk.ticketExpirationTime =
        std::chrono::system_clock::time_point(std::chrono::seconds(20));
    psk.ticketHandshakeTime = std::chrono::system_clock::time_point();
    psk.maxEarlyDataSize = 2;
    ServerHandshakeTest::SetUp();
  }

  void setupClientAndServerContext() override {
    cache->putPsk(kTestHostname.str(), psk);
    ticketCipher = makeTicketCipher();
    serverCtx->setTicketCipher(ticketCipher);
    clientCtx->setPskCache(cache);
    clientCtx->setSupportedAlpns({"h1q-fb"});
    serverCtx->setSupportedAlpns({"h1q-fb", "hq"});
  }

  virtual std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() = 0;

  std::shared_ptr<fizz::client::BasicPskCache> cache;
  folly::Promise<folly::Unit> promise;
  std::shared_ptr<fizz::server::TicketCipher> ticketCipher;
  fizz::client::CachedPsk psk;
};

class ServerHandshakeHRRTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeHRRTest() override = default;

  void setupClientAndServerContext() override {
    // Make a group mismatch happen.
    psk.group = fizz::NamedGroup::secp256r1;
    clientCtx->setSupportedGroups(
        {fizz::NamedGroup::secp256r1, fizz::NamedGroup::x25519});
    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setDefaultShares({fizz::NamedGroup::secp256r1});
    serverCtx->setSupportedGroups({fizz::NamedGroup::x25519});
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setSupportedAlpns({"h1q-fb"});
    serverCtx->setSupportedAlpns({"h1q-fb", "hq"});
    ServerHandshakePskTest::setupClientAndServerContext();
  }

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(true, promise.getFuture());
    return cipher;
  }
};

TEST_F(ServerHandshakeHRRTest, TestHRR) {
  auto rejectingCipher =
      dynamic_cast<AsyncRejectingTicketCipher*>(ticketCipher.get());
  rejectingCipher->setDecryptAsync(false, folly::makeFuture());
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);

  expectOneRttReadCipher(false);
  expectOneRttWriteCipher(true);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  EXPECT_EQ(handshake->getApplicationProtocol(), "h1q-fb");
  expectOneRttCipher(true);
}

TEST_F(ServerHandshakeHRRTest, TestAsyncHRR) {
  // Make an async ticket decryption operation.
  clientServerRound();

  promise.setValue();
  evb.loop();

  expectOneRttCipher(false);

  handshakeCv.wait();
  handshakeCv.reset();
  clientServerRound();
  serverClientRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  EXPECT_EQ(handshake->getApplicationProtocol(), "h1q-fb");
  expectOneRttCipher(true);
}

TEST_F(ServerHandshakeHRRTest, TestAsyncCancel) {
  // Make an async ticket decryption operation.
  clientServerRound();

  handshake->cancel();
  // Let's destroy the crypto state to make sure it is not referenced.
  conn->cryptoState.reset();

  promise.setValue();
  evb.loop();

  EXPECT_EQ(handshake->getApplicationProtocol(), folly::none);
  expectOneRttCipher(false);
}

class ServerHandshakeAsyncTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeAsyncTest() override = default;

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(false, folly::makeFuture());
    cipher->setEncryptAsync(true, promise.getFuture());
    return cipher;
  }
};

TEST_F(ServerHandshakeAsyncTest, TestAsyncCancel) {
  // Make an async ticket decryption operation.
  clientServerRound();
  serverClientRound();
  clientServerRound();

  handshake->cancel();
  // Let's destroy the crypto state to make sure it is not referenced.
  conn->cryptoState.reset();

  promise.setValue();
  evb.loop();

  EXPECT_EQ(conn->getDestructorGuardCount(), 0);
}

class ServerHandshakeAsyncErrorTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeAsyncErrorTest() override = default;

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(true, promise.getFuture());
    cipher->setDecryptError(true);
    return cipher;
  }
};

TEST_F(ServerHandshakeAsyncErrorTest, TestAsyncError) {
  clientServerRound();

  bool error = false;
  EXPECT_CALL(serverCallback, onCryptoEventAvailable())
      .WillRepeatedly(Invoke([&] {
        try {
          handshake->getOneRttReadCipher();
        } catch (std::exception&) {
          error = true;
        }
      }));
  promise.setValue();
  evb.loop();
  EXPECT_TRUE(error);
}

TEST_F(ServerHandshakeAsyncErrorTest, TestCancelOnAsyncError) {
  clientServerRound();

  EXPECT_CALL(serverCallback, onCryptoEventAvailable())
      .WillRepeatedly(Invoke([&] {
        handshake->cancel();
        // Let's destroy the crypto state to make sure it is not referenced.
        conn->cryptoState.reset();
      }));
  promise.setValue();
  evb.loop();
  EXPECT_THROW(handshake->getOneRttReadCipher(), std::runtime_error);
}

TEST_F(ServerHandshakeAsyncErrorTest, TestCancelWhileWaitingAsyncError) {
  clientServerRound();
  handshake->cancel();
  // Let's destroy the crypto state to make sure it is not referenced.
  conn->cryptoState.reset();

  promise.setValue();
  evb.loop();
  EXPECT_THROW(handshake->getOneRttReadCipher(), std::runtime_error);
}

class ServerHandshakeSyncErrorTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeSyncErrorTest() override = default;

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptError(true);
    cipher->setDecryptAsync(false, folly::makeFuture());
    return cipher;
  }
};

TEST_F(ServerHandshakeSyncErrorTest, TestError) {
  // Make an async ticket decryption operation.
  clientServerRound();
  evb.loop();
  EXPECT_THROW(handshake->getOneRttReadCipher(), std::runtime_error);
}

class ServerHandshakeZeroRttDefaultAppTokenValidatorTest
    : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeZeroRttDefaultAppTokenValidatorTest() override = default;

  /**
   * This cipher can currently resume only 1 connection.
   */
  class AcceptingTicketCipher : public fizz::server::TicketCipher {
   public:
    ~AcceptingTicketCipher() override = default;

    folly::Future<folly::Optional<
        std::pair<std::unique_ptr<folly::IOBuf>, std::chrono::seconds>>>
    encrypt(fizz::server::ResumptionState) const override {
      // Fake handshake, no need todo anything here.
      return std::make_pair(IOBuf::create(0), 2s);
    }

    void setPsk(fizz::client::CachedPsk psk) {
      resState.version = psk.version;
      resState.cipher = psk.cipher;
      resState.resumptionSecret = folly::IOBuf::copyBuffer(psk.secret);
      resState.alpn = psk.alpn;
      resState.ticketIssueTime = std::chrono::system_clock::time_point();
      resState.handshakeTime = std::chrono::system_clock::time_point();
      resState.serverCert = psk.serverCert;
    }

    folly::Future<std::pair<
        fizz::PskType,
        folly::Optional<fizz::server::ResumptionState>>>
    decrypt(std::unique_ptr<folly::IOBuf>) const override {
      return std::make_pair(fizz::PskType::Resumption, std::move(resState));
    }

   private:
    mutable fizz::server::ResumptionState resState;
  };

  void setupClientAndServerContext() override {
    clientCtx->setSendEarlyData(true);
    serverCtx->setEarlyDataSettings(
        true,
        fizz::server::ClockSkewTolerance{-1000ms, 1000ms},
        std::make_shared<fizz::server::AllowAllReplayReplayCache>());

    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setSupportedAlpns({"h1q-fb"});
    serverCtx->setSupportedAlpns({"h1q-fb", "hq"});
    ServerHandshakePskTest::setupClientAndServerContext();
  }

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AcceptingTicketCipher>();
    cipher->setPsk(psk);
    return cipher;
  }
};

TEST_F(
    ServerHandshakeZeroRttDefaultAppTokenValidatorTest,
    TestDefaultAppTokenValidatorRejectZeroRtt) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  expectZeroRttCipher(false, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);
}

class ServerHandshakeZeroRttTest
    : public ServerHandshakeZeroRttDefaultAppTokenValidatorTest {
  void initialize() override {
    auto validator =
        std::make_unique<fizz::server::test::MockAppTokenValidator>();
    validator_ = validator.get();
    handshake->initialize(&evb, &serverCallback, std::move(validator));
  }

 protected:
  fizz::server::test::MockAppTokenValidator* validator_;
};

TEST_F(ServerHandshakeZeroRttTest, TestResumption) {
  EXPECT_CALL(*validator_, validate(_)).WillOnce(Return(true));
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::KeysDerived);
  expectZeroRttCipher(true, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectZeroRttCipher(true, true);
}

TEST_F(ServerHandshakeZeroRttTest, TestRejectZeroRttNotEnabled) {
  auto realServerCtx =
      dynamic_cast<FizzServerHandshake*>(handshake)->getContext();
  auto nonConstServerCtx =
      const_cast<fizz::server::FizzServerContext*>(realServerCtx);
  nonConstServerCtx->setEarlyDataSettings(
      false, fizz::server::ClockSkewTolerance(), nullptr);
  EXPECT_CALL(*validator_, validate(_)).Times(0);
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  expectZeroRttCipher(false, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);
}

TEST_F(ServerHandshakeZeroRttTest, TestRejectZeroRttInvalidToken) {
  EXPECT_CALL(*validator_, validate(_)).WillOnce(Return(false));
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  expectZeroRttCipher(false, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);
}
} // namespace test
} // namespace quic
