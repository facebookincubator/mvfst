/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#include <quic/client/QuicClientTransport.h>
#include <quic/server/QuicServer.h>

#include <quic/api/test/Mocks.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/crypto/aead/test/Mocks.h>
#include <fizz/protocol/clock/test/Mocks.h>
#include <folly/futures/Future.h>
#include <folly/io/Cursor.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/client/handshake/test/MockQuicPskCache.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/FileQLogger.h>
#include <quic/logging/test/Mocks.h>
#include <quic/samples/echo/EchoHandler.h>
#include <quic/samples/echo/EchoServer.h>
#include <quic/state/test/MockQuicStats.h>
#include "quic/QuicConstants.h"

using namespace testing;
using namespace folly;
using namespace quic::samples;

namespace quic {
namespace test {

namespace {
std::vector<uint8_t> kInitialDstConnIdVecForRetryTest =
    {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
}

MATCHER_P(BufMatches, buf, "") {
  folly::IOBufEqualTo eq;
  return eq(*arg, buf);
}

class DestructionCallback
    : public std::enable_shared_from_this<DestructionCallback> {
 public:
  void markDestroyed() {
    destroyed_ = true;
  }

  bool isDestroyed() {
    return destroyed_;
  }

 private:
  bool destroyed_{false};
};

struct TestingParams {
  QuicVersion version;
  uint8_t dstConnIdSize;

  explicit TestingParams(QuicVersion versionIn, uint8_t dstConnIdSizeIn = 8)
      : version(versionIn), dstConnIdSize(dstConnIdSizeIn) {}
};

class TestingQuicClientTransport : public QuicClientTransport {
 public:
  TestingQuicClientTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connIdSize = kDefaultConnectionIdSize)
      : QuicClientTransport(
            evb,
            std::move(socket),
            std::move(handshakeFactory),
            connIdSize) {}

  ~TestingQuicClientTransport() override {
    if (destructionCallback_) {
      destructionCallback_->markDestroyed();
    }
  }

  const QuicClientConnectionState& getConn() const {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  QuicClientConnectionState& getNonConstConn() {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  const auto& getReadCallbacks() const {
    return readCallbacks_;
  }

  const auto& getDeliveryCallbacks() const {
    return deliveryCallbacks_;
  }

  auto getConnPendingWriteCallback() const {
    return connWriteCallback_;
  }

  auto getStreamPendingWriteCallbacks() const {
    return pendingWriteCallbacks_;
  }

  auto& idleTimeout() {
    return idleTimeout_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  auto& ackTimeout() {
    return ackTimeout_;
  }

  auto& happyEyeballsConnAttemptDelayTimeout() {
    return happyEyeballsConnAttemptDelayTimeout_;
  }

  auto& drainTimeout() {
    return drainTimeout_;
  }

  bool isClosed() const {
    return closeState_ == CloseState::CLOSED;
  }

  bool isDraining() const {
    return drainTimeout_.isScheduled();
  }

  auto& serverInitialParamsSet() {
    return getNonConstConn().serverInitialParamsSet_;
  }

  auto& peerAdvertisedInitialMaxData() {
    return getConn().peerAdvertisedInitialMaxData;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiLocal() const {
    return getConn().peerAdvertisedInitialMaxStreamDataBidiLocal;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiRemote() const {
    return getConn().peerAdvertisedInitialMaxStreamDataBidiRemote;
  }

  auto& peerAdvertisedInitialMaxStreamDataUni() const {
    return getConn().peerAdvertisedInitialMaxStreamDataUni;
  }

  void setDestructionCallback(
      std::shared_ptr<DestructionCallback> destructionCallback) {
    destructionCallback_ = destructionCallback;
  }

  void invokeOnDataAvailable(
      const folly::SocketAddress& addr,
      size_t len,
      bool truncated) {
    onDataAvailable(addr, len, truncated, OnDataAvailableParams());
  }

  void invokeOnNotifyDataAvailable(folly::AsyncUDPSocket& sock) {
    onNotifyDataAvailable(sock);
  }

 private:
  std::shared_ptr<DestructionCallback> destructionCallback_;
};

using StreamPair = std::pair<std::unique_ptr<folly::IOBuf>, StreamId>;

class QuicClientTransportIntegrationTest : public TestWithParam<TestingParams> {
 public:
  void SetUp() override {
    folly::ssl::init();

    // Fizz is the hostname for the server cert.
    hostname = "Fizz";
    serverCtx = test::createServerCtx();
    serverCtx->setSupportedAlpns({"h1q-fb", "hq"});
    server_ = createServer(ProcessId::ZERO);
    serverAddr = server_->getAddress();
    ON_CALL(clientConnCallback, onTransportReady()).WillByDefault(Invoke([&] {
      connected_ = true;
    }));

    clientCtx = createClientContext();
    verifier = createTestCertificateVerifier();
    client = createClient();
  }

  QuicVersion getVersion() {
    return GetParam().version;
  }

  std::shared_ptr<fizz::client::FizzClientContext> createClientContext() {
    clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setSupportedAlpns({"h1q-fb"});
    clientCtx->setClock(std::make_shared<NiceMock<fizz::test::MockClock>>());
    return clientCtx;
  }

  std::shared_ptr<TestingQuicClientTransport> createClient() {
    pskCache_ = std::make_shared<BasicQuicPskCache>();

    auto sock = std::make_unique<folly::AsyncUDPSocket>(&eventbase_);
    auto fizzClientContext = FizzClientQuicHandshakeContext::Builder()
                                 .setFizzClientContext(clientCtx)
                                 .setCertificateVerifier(verifier)
                                 .setPskCache(pskCache_)
                                 .build();
    client = std::make_shared<TestingQuicClientTransport>(
        &eventbase_,
        std::move(sock),
        std::move(fizzClientContext),
        GetParam().dstConnIdSize);
    client->setSupportedVersions({getVersion()});
    client->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    client->setHostname(hostname);
    client->addNewPeerAddress(serverAddr);
    auto transportSettings = client->getTransportSettings();
    transportSettings.attemptEarlyData = true;
    client->setTransportSettings(transportSettings);
    return client;
  }

  std::shared_ptr<QuicServer> createServer(ProcessId processId) {
    auto server = QuicServer::createQuicServer();
    auto transportSettings = server->getTransportSettings();
    auto statsFactory = std::make_unique<NiceMock<MockQuicStatsFactory>>();
    ON_CALL(*statsFactory, make()).WillByDefault(Invoke([&]() {
      auto newStatsCallback = std::make_unique<NiceMock<MockQuicStats>>();
      statsCallbacks_.push_back(newStatsCallback.get());
      return newStatsCallback;
    }));
    transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
    server->setTransportSettings(transportSettings);
    server->setQuicServerTransportFactory(
        std::make_unique<EchoServerTransportFactory>());
    server->setQuicUDPSocketFactory(
        std::make_unique<QuicSharedUDPSocketFactory>());
    server->setTransportStatsCallbackFactory(std::move(statsFactory));
    server->setFizzContext(serverCtx);
    server->setSupportedVersion({getVersion(), MVFST1});
    folly::SocketAddress addr("::1", 0);
    server->setProcessId(processId);
    server->start(addr, 1);
    server->waitUntilInitialized();
    return server;
  }

  void TearDown() override {
    std::thread t([&] { eventbase_.loopForever(); });
    SCOPE_EXIT {
      t.join();
    };
    if (connected_) {
      verifyTransportParameters();
    }
    server_->shutdown();
    server_ = nullptr;
    eventbase_.runInEventBaseThreadAndWait([&] { client = nullptr; });
    eventbase_.terminateLoopSoon();
  }

  void verifyTransportParameters() {
    EXPECT_EQ(client->getConn().peerIdleTimeout, kDefaultIdleTimeout);
  }

  void expectTransportCallbacks() {
    EXPECT_CALL(clientConnCallback, onReplaySafe());
  }

  void expectStatsCallbacks() {
    quicStats_ = std::make_shared<MockQuicStats>();
    EXPECT_CALL(*quicStats_, onPacketReceived()).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onPacketSent()).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
    EXPECT_CALL(*quicStats_, onQuicStreamClosed()).Times(1);
    EXPECT_CALL(*quicStats_, onRead(_)).Times(AtLeast(1));
    EXPECT_CALL(*quicStats_, onWrite(_)).Times(AtLeast(1));
    client->setTransportStatsCallback(quicStats_);
  }

  folly::Future<StreamPair> sendRequestAndResponse(
      std::unique_ptr<folly::IOBuf> data,
      StreamId streamid,
      MockReadCallback* readCb);

  void sendRequestAndResponseAndWait(
      folly::IOBuf& expectedData,
      std::unique_ptr<folly::IOBuf> sendData,
      StreamId streamid,
      MockReadCallback* readCb);

  void checkTransportSummaryEvent(const std::shared_ptr<FileQLogger>& qLogger) {
    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::TransportSummary, qLogger);
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogTransportSummaryEvent*>(tmp.get());

    uint64_t totalCryptoDataWritten = 0;
    uint64_t totalCryptoDataRecvd = 0;

    if (client->getConn().cryptoState) {
      totalCryptoDataWritten +=
          client->getConn().cryptoState->initialStream.currentWriteOffset;
      totalCryptoDataWritten +=
          client->getConn().cryptoState->handshakeStream.currentWriteOffset;
      totalCryptoDataWritten +=
          client->getConn().cryptoState->oneRttStream.currentWriteOffset;
      totalCryptoDataRecvd +=
          client->getConn().cryptoState->initialStream.maxOffsetObserved;
      totalCryptoDataRecvd +=
          client->getConn().cryptoState->handshakeStream.maxOffsetObserved;
      totalCryptoDataRecvd +=
          client->getConn().cryptoState->oneRttStream.maxOffsetObserved;
    }

    EXPECT_EQ(
        event->totalBytesSent, client->getConn().lossState.totalBytesSent);
    EXPECT_EQ(
        event->totalBytesRecvd, client->getConn().lossState.totalBytesRecvd);
    EXPECT_EQ(
        event->sumCurWriteOffset,
        client->getConn().flowControlState.sumCurWriteOffset);
    EXPECT_EQ(
        event->sumMaxObservedOffset,
        client->getConn().flowControlState.sumMaxObservedOffset);
    EXPECT_EQ(
        event->sumCurStreamBufferLen,
        client->getConn().flowControlState.sumCurStreamBufferLen);
    EXPECT_EQ(
        event->totalBytesRetransmitted,
        client->getConn().lossState.totalBytesRetransmitted);
    EXPECT_EQ(
        event->totalStreamBytesCloned,
        client->getConn().lossState.totalStreamBytesCloned);
    EXPECT_EQ(
        event->totalBytesCloned, client->getConn().lossState.totalBytesCloned);
    EXPECT_EQ(event->totalCryptoDataWritten, totalCryptoDataWritten);
    EXPECT_EQ(event->totalCryptoDataRecvd, totalCryptoDataRecvd);
  }

 protected:
  std::string hostname;
  folly::EventBase eventbase_;
  folly::SocketAddress serverAddr;
  NiceMock<MockConnectionCallback> clientConnCallback;
  NiceMock<MockReadCallback> readCb;
  std::shared_ptr<TestingQuicClientTransport> client;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;
  std::shared_ptr<fizz::client::FizzClientContext> clientCtx;
  std::shared_ptr<fizz::CertificateVerifier> verifier;
  std::shared_ptr<QuicPskCache> pskCache_;
  std::shared_ptr<QuicServer> server_;
  bool connected_{false};
  std::shared_ptr<MockQuicStats> quicStats_;
  std::vector<MockQuicStats*> statsCallbacks_;
};

class StreamData {
 public:
  BufQueue data;

  folly::Promise<StreamPair> promise;
  StreamId id;

  explicit StreamData(StreamId id) : id(id) {}

  void setException(
      const std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>&
          err) {
    promise.setException(std::runtime_error(toString(err)));
    delete this;
  }

  void append(std::unique_ptr<folly::IOBuf> buf, bool eof) {
    data.append(std::move(buf));
    if (eof) {
      promise.setValue(std::make_pair(data.move(), id));
      delete this;
    }
  }
};

folly::Future<StreamPair>
QuicClientTransportIntegrationTest::sendRequestAndResponse(
    std::unique_ptr<folly::IOBuf> data,
    StreamId streamId,
    MockReadCallback* readCallback) {
  client->setReadCallback(streamId, readCallback);
  client->writeChain(streamId, data->clone(), true, false);
  auto streamData = new StreamData(streamId);
  auto dataCopy = std::shared_ptr<folly::IOBuf>(std::move(data));
  EXPECT_CALL(*readCallback, readAvailable(streamId))
      .WillRepeatedly(
          Invoke([c = client.get(), id = streamId, streamData, dataCopy](
                     auto) mutable {
            auto readData = c->read(id, 1000);
            auto copy = readData->first->clone();
            LOG(INFO) << "Client received data="
                      << copy->moveToFbString().toStdString()
                      << " on stream=" << id
                      << " read=" << readData->first->computeChainDataLength()
                      << " sent=" << dataCopy->computeChainDataLength();
            streamData->append(std::move(readData->first), readData->second);
          }));
  ON_CALL(*readCallback, readError(streamId, _))
      .WillByDefault(Invoke([streamData](auto, auto err) mutable {
        streamData->setException(err);
      }));
  return streamData->promise.getFuture().within(20s);
}

void QuicClientTransportIntegrationTest::sendRequestAndResponseAndWait(
    folly::IOBuf& expectedData,
    std::unique_ptr<folly::IOBuf> sendData,
    StreamId streamId,
    MockReadCallback* readCallback) {
  auto f = sendRequestAndResponse(sendData->clone(), streamId, readCallback)
               .thenValue([&](StreamPair buf) {
                 EXPECT_TRUE(folly::IOBufEqualTo()(*buf.first, expectedData));
               })
               .ensure([&] { eventbase_.terminateLoopSoon(); });
  eventbase_.loopForever();
  std::move(f).get(1s);
}

TEST_P(QuicClientTransportIntegrationTest, NetworkTest) {
  expectTransportCallbacks();
  expectStatsCallbacks();
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    EXPECT_EQ(client->getConn().peerConnectionIds.size(), 1);
    EXPECT_EQ(
        *client->getConn().serverConnectionId,
        client->getConn().peerConnectionIds[0].connId);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, FlowControlLimitedTest) {
  expectTransportCallbacks();
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  client->setStreamFlowControlWindow(streamId, 256);
  auto data = IOBuf::create(4096);
  data->append(4096);
  memset(data->writableData(), 'a', data->length());

  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, ALPNTest) {
  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h1q-fb");
    client->close(folly::none);
    eventbase_.terminateLoopSoon();
  }));
  ASSERT_EQ(client->getAppProtocol(), folly::none);
  client->start(&clientConnCallback);
  eventbase_.loopForever();
}

TEST_P(QuicClientTransportIntegrationTest, TLSAlert) {
  verifier = nullptr;
  client = createClient();

  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  EXPECT_CALL(clientConnCallback, onConnectionError(_))
      .WillOnce(Invoke([&](const auto& errorCode) {
        LOG(ERROR) << "error: " << errorCode.second;
        const TransportErrorCode* transportError =
            errorCode.first.asTransportErrorCode();
        EXPECT_NE(transportError, nullptr);
        client->close(folly::none);
        this->checkTransportSummaryEvent(qLogger);

        eventbase_.terminateLoopSoon();
      }));

  ASSERT_EQ(client->getAppProtocol(), folly::none);

  client->start(&clientConnCallback);
  eventbase_.loopForever();
}

TEST_P(QuicClientTransportIntegrationTest, BadServerTest) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  // Point the client to a bad server.
  client->addNewPeerAddress(SocketAddress("127.0.0.1", 14114));
  EXPECT_CALL(clientConnCallback, onConnectionError(_))
      .WillOnce(Invoke([&](const auto& errorCode) {
        LOG(ERROR) << "error: " << errorCode.second;
        const LocalErrorCode* localError = errorCode.first.asLocalErrorCode();
        EXPECT_NE(localError, nullptr);
        this->checkTransportSummaryEvent(qLogger);
      }));
  client->start(&clientConnCallback);
  eventbase_.loop();
}

TEST_P(QuicClientTransportIntegrationTest, NetworkTestConnected) {
  expectTransportCallbacks();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  TransportSettings settings;
  settings.connectUDP = true;
  client->setTransportSettings(settings);
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
}

TEST_P(QuicClientTransportIntegrationTest, SetTransportSettingsAfterStart) {
  expectTransportCallbacks();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  TransportSettings settings;
  settings.connectUDP = true;
  client->setTransportSettings(settings);
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  settings.connectUDP = false;
  client->setTransportSettings(settings);
  EXPECT_TRUE(client->getTransportSettings().connectUDP);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttSuccess) {
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  setupZeroRttOnServerCtx(*serverCtx, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  folly::Optional<std::string> alpn = std::string("h1q-fb");
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>& alpnToValidate, const Buf&) {
        performedValidation = true;
        EXPECT_EQ(alpnToValidate, alpn);
        return true;
      },
      []() -> Buf { return nullptr; });
  client->start(&clientConnCallback);
  EXPECT_TRUE(performedValidation);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h1q-fb");
    CHECK(client->getConn().zeroRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->good());
  EXPECT_FALSE(client->replaySafe());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  if (GetParam().version == QuicVersion::MVFST_D24) {
    EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  } else {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
  }
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttRejection) {
  expectTransportCallbacks();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) {
        performedValidation = true;
        return true;
      },
      []() -> Buf { return nullptr; });
  client->start(&clientConnCallback);
  EXPECT_TRUE(performedValidation);
  CHECK(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
  client->serverInitialParamsSet() = false;

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    ASSERT_EQ(client->getAppProtocol(), "h1q-fb");
    CHECK(client->getConn().zeroRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  EXPECT_TRUE(client->getConn().zeroRttWriteCipher);
  EXPECT_TRUE(client->good());
  EXPECT_FALSE(client->replaySafe());

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  // Rejection means that we will unset the zero rtt cipher.
  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttNotAttempted) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  client->getNonConstConn().transportSettings.attemptEarlyData = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) {
        EXPECT_TRUE(false);
        return true;
      },
      []() -> Buf { return nullptr; });
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, TestZeroRttInvalidAppParams) {
  expectTransportCallbacks();
  auto cachedPsk = setupZeroRttOnClientCtx(*clientCtx, hostname);
  pskCache_->putPsk(hostname, cachedPsk);
  // Change the ctx
  server_->setFizzContext(serverCtx);
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) {
        performedValidation = true;
        return false;
      },
      []() -> Buf { return nullptr; });
  client->start(&clientConnCallback);
  EXPECT_TRUE(performedValidation);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    EXPECT_FALSE(client->getConn().zeroRttWriteCipher);
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->serverInitialParamsSet());
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxData(), kDefaultConnectionWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiLocal(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataBidiRemote(),
      kDefaultStreamWindowSize);
  EXPECT_EQ(
      client->peerAdvertisedInitialMaxStreamDataUni(),
      kDefaultStreamWindowSize);
}

TEST_P(QuicClientTransportIntegrationTest, ChangeEventBase) {
  NiceMock<MockReadCallback> readCb2;
  folly::ScopedEventBaseThread newEvb;
  expectTransportCallbacks();
  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->isDetachable());
  client->detachEventBase();
  folly::Baton<> baton;
  bool responseRecvd = false;
  VLOG(10) << "changing threads";
  newEvb.getEventBase()->runInEventBaseThreadAndWait([&] {
    client->attachEventBase(newEvb.getEventBase());
    auto streamId2 = client->createBidirectionalStream().value();
    sendRequestAndResponse(data->clone(), streamId2, &readCb2)
        .thenValue([&](StreamPair buf) {
          responseRecvd = true;
          EXPECT_TRUE(folly::IOBufEqualTo()(*buf.first, *expected));
        })
        .ensure([&] { baton.post(); });
  });
  baton.wait();
  EXPECT_TRUE(responseRecvd);
}

TEST_P(QuicClientTransportIntegrationTest, ResetClient) {
  expectTransportCallbacks();
  auto server2 = createServer(ProcessId::ONE);
  SCOPE_EXIT {
    server2->shutdown();
    server2 = nullptr;
  };

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // change the address to a new server which does not have the connection.
  auto server2Addr = server2->getAddress();
  client->getNonConstConn().peerAddress = server2Addr;

  NiceMock<MockReadCallback> readCb2;
  bool resetRecvd = false;
  auto streamId2 = client->createBidirectionalStream().value();
  auto f2 = sendRequestAndResponse(data->clone(), streamId2, &readCb2)
                .thenValue([&](StreamPair) { resetRecvd = false; })
                .thenError(
                    folly::tag_t<std::runtime_error>{},
                    [&](const std::runtime_error& e) {
                      LOG(INFO) << e.what();
                      resetRecvd = true;
                    })
                .ensure([&] { eventbase_.terminateLoopSoon(); });
  eventbase_.loopForever();
  std::move(f2).get(5s);
  EXPECT_TRUE(resetRecvd);
}

TEST_P(QuicClientTransportIntegrationTest, TestStatelessResetToken) {
  folly::Optional<StatelessResetToken> token1, token2;

  expectTransportCallbacks();
  auto server2 = createServer(ProcessId::ONE);
  SCOPE_EXIT {
    server2->shutdown();
    server2 = nullptr;
  };

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    token1 = client->getConn().statelessResetToken;
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // change the address to a new server which does not have the connection.
  auto server2Addr = server2->getAddress();
  client->getNonConstConn().peerAddress = server2Addr;

  NiceMock<MockReadCallback> readCb2;
  bool resetRecvd = false;
  auto streamId2 = client->createBidirectionalStream().value();
  sendRequestAndResponse(data->clone(), streamId2, &readCb2)
      .thenValue([&](StreamPair) { resetRecvd = false; })
      .thenError(
          folly::tag_t<std::runtime_error>{},
          [&](const std::runtime_error& e) {
            LOG(INFO) << e.what();
            resetRecvd = true;
            token2 = client->getConn().statelessResetToken;
          })
      .ensure([&] { eventbase_.terminateLoopSoon(); });
  eventbase_.loopForever();

  EXPECT_TRUE(resetRecvd);
  EXPECT_TRUE(token1.has_value());
  EXPECT_TRUE(token2.has_value());
  EXPECT_EQ(token1.value(), token2.value());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityDisabledTest) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = false;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = false;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityDisabledTest2) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = true;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = false;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityDisabledTest3) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = false;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = true;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, PartialReliabilityEnabledTest) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = true;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = true;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);

  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);
  EXPECT_TRUE(client->isPartiallyReliableTransport());
}

TEST_P(QuicClientTransportIntegrationTest, D6DEnabledTest) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.d6dConfig.enabled = true;
  client->setTransportSettings(settings);

  TransportSettings serverSettings;
  serverSettings.d6dConfig.enabled = true;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  // we only use 1 worker in test
  client->start(&clientConnCallback);
  EXPECT_EQ(1, statsCallbacks_.size());
  EXPECT_CALL(*statsCallbacks_[0], onConnectionD6DStarted())
      .WillOnce(Invoke([&] { eventbase_.terminateLoopSoon(); }));
  eventbase_.loopForever();
}

TEST_P(
    QuicClientTransportIntegrationTest,
    PartialReliabilityEnableDisableRunTimeTest) {
  expectTransportCallbacks();
  TransportSettings settings;
  settings.connectUDP = true;
  settings.partialReliabilityEnabled = true;
  client->setTransportSettings(settings);

  // Enable PR on server.
  TransportSettings serverSettings;
  serverSettings.partialReliabilityEnabled = true;
  serverSettings.statelessResetTokenSecret = getRandSecret();
  server_->setTransportSettings(serverSettings);

  client->start(&clientConnCallback);
  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  auto streamId = client->createBidirectionalStream().value();
  auto data = IOBuf::copyBuffer("hello");
  auto expected = std::shared_ptr<IOBuf>(IOBuf::copyBuffer("echo "));
  expected->prependChain(data->clone());
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // Client successfully negotiated partial reliability on connection.
  EXPECT_TRUE(client->isPartiallyReliableTransport());

  // Disable PR on server.
  server_->enablePartialReliability(false);

  // Re-connect.
  client = createClient();
  expectTransportCallbacks();
  client->setTransportSettings(settings);
  client->start(&clientConnCallback);
  EXPECT_CALL(clientConnCallback, onTransportReady()).WillOnce(Invoke([&] {
    CHECK(client->getConn().oneRttWriteCipher);
    eventbase_.terminateLoopSoon();
  }));
  eventbase_.loopForever();

  streamId = client->createBidirectionalStream().value();
  sendRequestAndResponseAndWait(*expected, data->clone(), streamId, &readCb);

  // Second connection should not successfully negotiate partial reliability,
  // even though client still has it locally enabled.
  EXPECT_FALSE(client->isPartiallyReliableTransport());
}

INSTANTIATE_TEST_CASE_P(
    QuicClientTransportIntegrationTests,
    QuicClientTransportIntegrationTest,
    ::testing::Values(
        TestingParams(QuicVersion::MVFST),
        TestingParams(QuicVersion::MVFST_D24),
        TestingParams(QuicVersion::QUIC_DRAFT),
        TestingParams(QuicVersion::QUIC_DRAFT, 0)));

// Simulates a simple 1rtt handshake without needing to get any handshake bytes
// from the server.
class FakeOneRttHandshakeLayer : public FizzClientHandshake {
 public:
  explicit FakeOneRttHandshakeLayer(
      QuicClientConnectionState* conn,
      std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
      : FizzClientHandshake(conn, std::move(fizzContext)) {}

  folly::Optional<CachedServerTransportParameters> connectImpl(
      folly::Optional<std::string> hostname) override {
    // Look up psk
    folly::Optional<QuicCachedPsk> quicCachedPsk = getPsk(hostname);

    folly::Optional<CachedServerTransportParameters> transportParams;
    if (quicCachedPsk) {
      transportParams = std::move(quicCachedPsk->transportParams);
    }

    getFizzState().sni() = hostname;

    connected_ = true;
    writeDataToQuicStream(
        getClientConn()->cryptoState->initialStream, IOBuf::copyBuffer("CHLO"));
    createServerTransportParameters();
    return transportParams;
  }

  void createServerTransportParameters() {
    TransportParameter maxStreamDataBidiLocal = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        maxInitialStreamData);
    TransportParameter maxStreamDataBidiRemote = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        maxInitialStreamData);
    TransportParameter maxStreamDataUni = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        maxInitialStreamData);
    TransportParameter maxStreamsBidi = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi, maxInitialStreamsBidi);
    TransportParameter maxStreamsUni = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni, maxInitialStreamsUni);
    TransportParameter maxData = encodeIntegerParameter(
        TransportParameterId::initial_max_data, connWindowSize);
    std::vector<TransportParameter> parameters;
    parameters.push_back(std::move(maxStreamDataBidiLocal));
    parameters.push_back(std::move(maxStreamDataBidiRemote));
    parameters.push_back(std::move(maxStreamDataUni));
    parameters.push_back(std::move(maxStreamsBidi));
    parameters.push_back(std::move(maxStreamsUni));
    parameters.push_back(std::move(maxData));
    parameters.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout, kDefaultIdleTimeout.count()));
    parameters.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize));
    ServerTransportParameters params;
    StatelessResetToken testStatelessResetToken = generateStatelessResetToken();
    TransportParameter statelessReset;
    statelessReset.parameter = TransportParameterId::stateless_reset_token;
    statelessReset.value = folly::IOBuf::copyBuffer(testStatelessResetToken);
    parameters.push_back(std::move(statelessReset));

    params.parameters = std::move(parameters);
    params_ = std::move(params);
  }

  void setServerTransportParams(ServerTransportParameters params) {
    params_ = std::move(params);
  }

  void setOneRttWriteCipher(std::unique_ptr<Aead> oneRttWriteCipher) {
    oneRttWriteCipher_ = std::move(oneRttWriteCipher);
  }

  void setOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher) {
    getClientConn()->readCodec->setOneRttReadCipher(
        std::move(oneRttReadCipher));
  }

  void setHandshakeReadCipher(std::unique_ptr<Aead> handshakeReadCipher) {
    getClientConn()->readCodec->setHandshakeReadCipher(
        std::move(handshakeReadCipher));
  }

  void setHandshakeWriteCipher(std::unique_ptr<Aead> handshakeWriteCipher) {
    getClientConn()->handshakeWriteCipher = std::move(handshakeWriteCipher);
  }

  void setZeroRttWriteCipher(std::unique_ptr<Aead> zeroRttWriteCipher) {
    getClientConn()->zeroRttWriteCipher = std::move(zeroRttWriteCipher);
  }

  void setZeroRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher) {
    getClientConn()->zeroRttWriteHeaderCipher =
        std::move(zeroRttWriteHeaderCipher);
  }

  void setHandshakeReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher) {
    getClientConn()->readCodec->setHandshakeHeaderCipher(
        std::move(handshakeReadHeaderCipher));
  }

  void setHandshakeWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher) {
    getClientConn()->handshakeWriteHeaderCipher =
        std::move(handshakeWriteHeaderCipher);
  }

  void setOneRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher) {
    oneRttWriteHeaderCipher_ = std::move(oneRttWriteHeaderCipher);
  }

  void setOneRttReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher) {
    getClientConn()->readCodec->setOneRttHeaderCipher(
        std::move(oneRttReadHeaderCipher));
  }

  void setZeroRttRejected(bool rejected) {
    setZeroRttRejectedForTest(rejected);
    if (rejected) {
      createServerTransportParameters();
    }
  }

  void doHandshake(std::unique_ptr<folly::IOBuf>, EncryptionLevel) override {
    EXPECT_EQ(writeBuf.get(), nullptr);
    QuicClientConnectionState* conn = getClientConn();
    if (!conn->oneRttWriteCipher) {
      conn->oneRttWriteCipher = std::move(oneRttWriteCipher_);
      conn->oneRttWriteHeaderCipher = std::move(oneRttWriteHeaderCipher_);
    }
    if (getPhase() == Phase::Initial) {
      conn->handshakeWriteCipher = test::createNoOpAead();
      conn->handshakeWriteHeaderCipher = test::createNoOpHeaderCipher();
      conn->readCodec->setHandshakeReadCipher(test::createNoOpAead());
      conn->readCodec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
      writeDataToQuicStream(
          conn->cryptoState->handshakeStream,
          IOBuf::copyBuffer("ClientFinished"));
      handshakeInitiated();
    }
  }

  bool connectInvoked() {
    return connected_;
  }

  folly::Optional<ServerTransportParameters> getServerTransportParams()
      override {
    return params_;
  }

  void triggerOnNewCachedPsk() {
    fizz::client::NewCachedPsk psk;
    onNewCachedPsk(psk);
  }

  std::unique_ptr<folly::IOBuf> writeBuf;

  bool connected_{false};
  QuicVersion negotiatedVersion{QuicVersion::MVFST};
  uint64_t maxRecvPacketSize{kDefaultMaxUDPPayload};
  uint64_t maxInitialStreamData{kDefaultStreamWindowSize};
  uint64_t connWindowSize{kDefaultConnectionWindowSize};
  uint64_t maxInitialStreamsBidi{std::numeric_limits<uint32_t>::max()};
  uint64_t maxInitialStreamsUni{std::numeric_limits<uint32_t>::max()};
  folly::Optional<ServerTransportParameters> params_;

  std::unique_ptr<Aead> oneRttWriteCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;

  FizzCryptoFactory cryptoFactory_;
  const CryptoFactory& getCryptoFactory() const override {
    return cryptoFactory_;
  }

  // Implement virtual methods we don't intend to use.
  bool isTLSResumed() const override {
    throw std::runtime_error("isTLSResumed not implemented");
  }
  EncryptionLevel getReadRecordLayerEncryptionLevel() override {
    throw std::runtime_error(
        "getReadRecordLayerEncryptionLevel not implemented");
  }
  const folly::Optional<std::string>& getApplicationProtocol() const override {
    throw std::runtime_error("getApplicationProtocol not implemented");
  }
  void processSocketData(folly::IOBufQueue&) override {
    throw std::runtime_error("processSocketData not implemented");
  }
  bool matchEarlyParameters() override {
    throw std::runtime_error("matchEarlyParameters not implemented");
  }
  std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind, folly::ByteRange) override {
    throw std::runtime_error("buildCiphers not implemented");
  }
};

class QuicClientTransportTest : public Test {
 public:
  struct TestReadData {
    std::unique_ptr<folly::IOBuf> data;
    folly::SocketAddress addr;
    folly::Optional<int> err;

    TestReadData(folly::ByteRange dataIn, const folly::SocketAddress& addrIn)
        : data(folly::IOBuf::copyBuffer(dataIn)), addr(addrIn) {}

    explicit TestReadData(int errIn) : err(errIn) {}
  };

  QuicClientTransportTest()
      : eventbase_(std::make_unique<folly::EventBase>()) {}

  std::shared_ptr<FizzClientQuicHandshakeContext> getFizzClientContext() {
    if (!fizzClientContext) {
      fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(createTestCertificateVerifier())
              .setPskCache(getPskCache())
              .build();
    }

    return fizzClientContext;
  }

  virtual std::shared_ptr<QuicPskCache> getPskCache() {
    return nullptr;
  }

  void SetUp() override final {
    auto socket = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
        eventbase_.get());
    sock = socket.get();

    client = TestingQuicClientTransport::newClient<TestingQuicClientTransport>(
        eventbase_.get(), std::move(socket), getFizzClientContext());
    destructionCallback = std::make_shared<DestructionCallback>();
    client->setDestructionCallback(destructionCallback);
    client->setSupportedVersions(
        {QuicVersion::MVFST, MVFST1, QuicVersion::QUIC_DRAFT});
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    ON_CALL(*sock, resumeRead(_))
        .WillByDefault(SaveArg<0>(&networkReadCallback));
    ON_CALL(*sock, address()).WillByDefault(ReturnRef(serverAddr));
    ON_CALL(*sock, recvmsg(_, _))
        .WillByDefault(Invoke([&](struct msghdr* msg, int) -> ssize_t {
          DCHECK_GT(msg->msg_iovlen, 0);
          if (socketReads.empty()) {
            errno = EAGAIN;
            return -1;
          }
          if (socketReads[0].err) {
            errno = *socketReads[0].err;
            return -1;
          }
          auto testData = std::move(socketReads[0].data);
          testData->coalesce();
          size_t testDataLen = testData->length();
          memcpy(
              msg->msg_iov[0].iov_base, testData->data(), testData->length());
          if (msg->msg_name) {
            socklen_t msg_len = socketReads[0].addr.getAddress(
                static_cast<sockaddr_storage*>(msg->msg_name));
            msg->msg_namelen = msg_len;
          }
          socketReads.pop_front();
          return testDataLen;
        }));
    EXPECT_EQ(client->getConn().selfConnectionIds.size(), 1);
    EXPECT_EQ(
        client->getConn().selfConnectionIds[0].connId,
        *client->getConn().clientConnectionId);
    EXPECT_EQ(client->getConn().peerConnectionIds.size(), 0);

    SetUpChild();
  }

  virtual void SetUpChild() {}

  virtual void setupCryptoLayer() {
    // Fake that the handshake has already occured and fix the keys.
    mockClientHandshake = new FakeOneRttHandshakeLayer(
        &client->getNonConstConn(), getFizzClientContext());
    client->getNonConstConn().clientHandshakeLayer = mockClientHandshake;
    client->getNonConstConn().handshakeLayer.reset(mockClientHandshake);
    setFakeHandshakeCiphers();
    // Allow ignoring path mtu for testing negotiation.
    client->getNonConstConn().transportSettings.canIgnorePathMTU = true;
  }

  virtual void setFakeHandshakeCiphers() {
    auto readAead = test::createNoOpAead();
    auto writeAead = test::createNoOpAead();
    auto handshakeReadAead = test::createNoOpAead();
    auto handshakeWriteAead = test::createNoOpAead();
    mockClientHandshake->setHandshakeReadCipher(std::move(handshakeReadAead));
    mockClientHandshake->setHandshakeWriteCipher(std::move(handshakeWriteAead));
    mockClientHandshake->setOneRttReadCipher(std::move(readAead));
    mockClientHandshake->setOneRttWriteCipher(std::move(writeAead));

    mockClientHandshake->setHandshakeReadHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setHandshakeWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttReadHeaderCipher(
        test::createNoOpHeaderCipher());
  }

  virtual void setUpSocketExpectations() {
    EXPECT_CALL(*sock, setReuseAddr(false));
    EXPECT_CALL(*sock, bind(_, _));
    EXPECT_CALL(*sock, dontFragment(true));
    EXPECT_CALL(*sock, setErrMessageCallback(client.get()));
    EXPECT_CALL(*sock, resumeRead(client.get()));
    EXPECT_CALL(*sock, setErrMessageCallback(nullptr));
    EXPECT_CALL(*sock, write(_, _)).Times(AtLeast(1));
  }

  virtual void start() {
    EXPECT_CALL(clientConnCallback, onTransportReady());
    EXPECT_CALL(clientConnCallback, onReplaySafe());
    setUpSocketExpectations();
    client->start(&clientConnCallback);
    setConnectionIds();
    EXPECT_TRUE(client->idleTimeout().isScheduled());

    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
    performFakeHandshake();
    EXPECT_TRUE(
        client->getConn().readCodec->getStatelessResetToken().has_value());
    EXPECT_TRUE(client->getConn().statelessResetToken.has_value());
  }

  void setConnectionIds() {
    originalConnId = client->getConn().clientConnectionId;
    ServerConnectionIdParams params(0, 0, 0);
    serverChosenConnId = *connIdAlgo_->encodeConnectionId(params);
  }

  void recvServerHello(const folly::SocketAddress& addr) {
    auto serverHello = IOBuf::copyBuffer("Fake SHLO");
    PacketNum nextPacketNum = initialPacketNum++;
    auto& aead = getInitialCipher();
    auto packet = packetToBufCleartext(
        createCryptoPacket(
            *serverChosenConnId,
            *originalConnId,
            nextPacketNum,
            version,
            ProtectionType::Initial,
            *serverHello,
            aead,
            0 /* largestAcked */),
        aead,
        getInitialHeaderCipher(),
        nextPacketNum);
    deliverData(addr, packet->coalesce());
  }

  ConnectionId recvServerRetry(const folly::SocketAddress& addr) {
    // Make the server send a retry packet to the client. The server chooses a
    // connection id that the client must use in all future initial packets.
    std::vector<uint8_t> serverConnIdVec = {
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5};
    ConnectionId serverCid(serverConnIdVec);

    std::string retryToken = "token";
    std::string integrityTag =
        "\xd1\x69\x26\xd8\x1f\x6f\x9c\xa2\x95\x3a\x8a\xa4\x57\x5e\x1e\x49";

    folly::IOBuf retryPacketBuf;
    BufAppender appender(&retryPacketBuf, 100);
    appender.writeBE<uint8_t>(0xFF);
    appender.writeBE<QuicVersionType>(static_cast<QuicVersionType>(0xFF00001D));
    appender.writeBE<uint8_t>(0);
    appender.writeBE<uint8_t>(serverConnIdVec.size());
    appender.push(serverConnIdVec.data(), serverConnIdVec.size());
    appender.push((const uint8_t*)retryToken.data(), retryToken.size());
    appender.push((const uint8_t*)integrityTag.data(), integrityTag.size());
    deliverData(addr, retryPacketBuf.coalesce());
    return serverCid;
  }

  void recvServerHello() {
    recvServerHello(serverAddr);
  }

  void recvTicket(folly::Optional<uint64_t> offsetOverride = folly::none) {
    auto negotiatedVersion = *client->getConn().version;
    auto ticket = IOBuf::copyBuffer("NST");
    auto packet = packetToBuf(createCryptoPacket(
        *serverChosenConnId,
        *originalConnId,
        appDataPacketNum++,
        negotiatedVersion,
        ProtectionType::KeyPhaseZero,
        *ticket,
        *createNoOpAead(),
        0 /* largestAcked */,
        offsetOverride
            ? *offsetOverride
            : client->getConn().cryptoState->oneRttStream.currentReadOffset));
    deliverData(packet->coalesce());
  }

  void performFakeHandshake(const folly::SocketAddress& addr) {
    // Create a fake server response to trigger fetching keys.
    recvServerHello(addr);
    assertWritten(false, LongHeader::Types::Handshake);

    verifyTransportParameters(
        kDefaultConnectionWindowSize,
        kDefaultStreamWindowSize,
        kDefaultIdleTimeout,
        kDefaultAckDelayExponent,
        mockClientHandshake->maxRecvPacketSize);
    verifyCiphers();
    socketWrites.clear();
  }

  void performFakeHandshake() {
    performFakeHandshake(serverAddr);
  }

  void verifyTransportParameters(
      uint64_t connFlowControl,
      uint64_t initialStreamFlowControl,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxPacketSize) {
    EXPECT_EQ(
        client->getConn().flowControlState.peerAdvertisedMaxOffset,
        connFlowControl);
    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
        initialStreamFlowControl);
    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
        initialStreamFlowControl);

    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
        initialStreamFlowControl);
    EXPECT_EQ(client->getConn().peerIdleTimeout.count(), idleTimeout.count());
    EXPECT_EQ(client->getConn().peerAckDelayExponent, ackDelayExponent);
    EXPECT_EQ(client->getConn().udpSendPacketLen, maxPacketSize);
  }

  void verifyCiphers() {
    EXPECT_NE(client->getConn().oneRttWriteCipher, nullptr);
    EXPECT_NE(client->getConn().handshakeWriteCipher, nullptr);
    EXPECT_NE(client->getConn().handshakeWriteHeaderCipher, nullptr);
    EXPECT_NE(client->getConn().oneRttWriteHeaderCipher, nullptr);

    EXPECT_NE(client->getConn().readCodec->getHandshakeHeaderCipher(), nullptr);
    EXPECT_NE(client->getConn().readCodec->getOneRttHeaderCipher(), nullptr);
  }

  void deliverDataWithoutErrorCheck(
      const folly::SocketAddress& addr,
      folly::ByteRange data,
      bool writes = true) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(TestReadData(data, addr));
    networkReadCallback->onNotifyDataAvailable(*sock);
    if (writes) {
      loopForWrites();
    }
  }

  void deliverNetworkError(int err) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(TestReadData(err));
    networkReadCallback->onNotifyDataAvailable(*sock);
  }

  void deliverDataWithoutErrorCheck(folly::ByteRange data, bool writes = true) {
    deliverDataWithoutErrorCheck(serverAddr, std::move(data), writes);
  }

  void deliverData(
      const folly::SocketAddress& addr,
      folly::ByteRange data,
      bool writes = true) {
    deliverDataWithoutErrorCheck(addr, std::move(data), writes);
    if (client->getConn().localConnectionError) {
      bool idleTimeout = false;
      const LocalErrorCode* localError =
          client->getConn().localConnectionError->first.asLocalErrorCode();
      if (localError) {
        idleTimeout = (*localError == LocalErrorCode::IDLE_TIMEOUT);
      }
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(client->getConn().localConnectionError->first));
      }
    }
  }

  void deliverData(folly::ByteRange data, bool writes = true) {
    deliverData(serverAddr, std::move(data), writes);
  }

  void loopForWrites() {
    // Loop the evb once to give writes some time to do their thing.
    eventbase_->loopOnce(EVLOOP_NONBLOCK);
  }

  void assertWritten(
      bool shortHeader,
      folly::Optional<LongHeader::Types> longHeader) {
    size_t numShort = 0;
    size_t numLong = 0;
    size_t numOthers = 0;
    if (!socketWrites.empty()) {
      auto& write = socketWrites.back();
      if (shortHeader && verifyShortHeader(*write)) {
        numShort++;
      } else if (longHeader && verifyLongHeader(*write, *longHeader)) {
        numLong++;
      } else {
        numOthers++;
      }
    }
    if (shortHeader) {
      EXPECT_GT(numShort, 0);
    }
    if (longHeader) {
      EXPECT_GT(numLong, 0);
    }
    EXPECT_EQ(numOthers, 0);
  }

  RegularQuicPacket* parseRegularQuicPacket(CodecResult& codecResult) {
    return codecResult.regularPacket();
  }

  void verifyShortPackets(AckBlocks& sentPackets) {
    AckStates ackStates;
    for (auto& write : socketWrites) {
      auto packetQueue = bufToQueue(write->clone());
      auto codecResult =
          makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
      auto parsedPacket = parseRegularQuicPacket(codecResult);
      if (!parsedPacket) {
        continue;
      }
      PacketNum packetNumSent = parsedPacket->header.getPacketSequenceNum();
      sentPackets.insert(packetNumSent);
      verifyShortHeader(*write);
    }
  }

  bool verifyLongHeader(
      folly::IOBuf& buf,
      typename LongHeader::Types headerType) {
    AckStates ackStates;
    auto packetQueue = bufToQueue(buf.clone());
    auto codecResult =
        makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
    auto parsedPacket = parseRegularQuicPacket(codecResult);
    if (!parsedPacket) {
      return false;
    }
    auto longHeader = parsedPacket->header.asLong();
    return longHeader && longHeader->getHeaderType() == headerType;
  }

  bool verifyShortHeader(folly::IOBuf& buf) {
    AckStates ackStates;
    auto packetQueue = bufToQueue(buf.clone());
    auto codecResult =
        makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
    auto parsedPacket = parseRegularQuicPacket(codecResult);
    if (!parsedPacket) {
      return false;
    }
    return parsedPacket->header.asShort();
  }

  std::unique_ptr<QuicReadCodec> makeHandshakeCodec() {
    FizzCryptoFactory cryptoFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    codec->setClientConnectionId(*originalConnId);
    codec->setInitialReadCipher(cryptoFactory.getClientInitialCipher(
        *client->getConn().initialDestinationConnectionId, QuicVersion::MVFST));
    codec->setInitialHeaderCipher(cryptoFactory.makeClientInitialHeaderCipher(
        *client->getConn().initialDestinationConnectionId, QuicVersion::MVFST));
    codec->setHandshakeReadCipher(test::createNoOpAead());
    codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
    return codec;
  }

  std::unique_ptr<QuicReadCodec> makeEncryptedCodec(
      bool handshakeCipher = false) {
    FizzCryptoFactory cryptoFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    std::unique_ptr<Aead> handshakeReadCipher;
    codec->setClientConnectionId(*originalConnId);
    codec->setOneRttReadCipher(test::createNoOpAead());
    codec->setOneRttHeaderCipher(test::createNoOpHeaderCipher());
    codec->setZeroRttReadCipher(test::createNoOpAead());
    codec->setZeroRttHeaderCipher(test::createNoOpHeaderCipher());
    if (handshakeCipher) {
      codec->setInitialReadCipher(cryptoFactory.getClientInitialCipher(
          *client->getConn().initialDestinationConnectionId,
          QuicVersion::MVFST));
      codec->setInitialHeaderCipher(cryptoFactory.makeClientInitialHeaderCipher(
          *client->getConn().initialDestinationConnectionId,
          QuicVersion::MVFST));
      codec->setHandshakeReadCipher(test::createNoOpAead());
      codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
    }
    return codec;
  }

  const Aead& getInitialCipher() {
    return *client->getConn().readCodec->getInitialCipher();
  }

  const PacketNumberCipher& getInitialHeaderCipher() {
    return *client->getConn().readCodec->getInitialHeaderCipher();
  }

  void expectQuicStatsPacketDrop(
      QuicTransportStatsCallback::PacketDropReason expectedReason) {
    auto quicStats = std::make_shared<NiceMock<MockQuicStats>>();
    EXPECT_CALL(*quicStats, onPacketDropped(_))
        .WillOnce(
            Invoke([=](QuicTransportStatsCallback::PacketDropReason reason) {
              EXPECT_EQ(expectedReason, reason);
            }));
    client->setTransportStatsCallback(quicStats);
  }

 protected:
  std::vector<std::unique_ptr<folly::IOBuf>> socketWrites;
  std::deque<TestReadData> socketReads;
  NiceMock<MockDeliveryCallback> deliveryCallback;
  NiceMock<MockReadCallback> readCb;
  NiceMock<MockConnectionCallback> clientConnCallback;
  folly::test::MockAsyncUDPSocket* sock;
  std::shared_ptr<DestructionCallback> destructionCallback;
  std::unique_ptr<folly::EventBase> eventbase_;
  SocketAddress serverAddr{"127.0.0.1", 443};
  AsyncUDPSocket::ReadCallback* networkReadCallback{nullptr};
  FakeOneRttHandshakeLayer* mockClientHandshake;
  std::shared_ptr<FizzClientQuicHandshakeContext> fizzClientContext;
  std::shared_ptr<TestingQuicClientTransport> client;
  PacketNum initialPacketNum{0}, handshakePacketNum{0}, appDataPacketNum{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  folly::Optional<ConnectionId> originalConnId;
  folly::Optional<ConnectionId> serverChosenConnId;
  QuicVersion version{QuicVersion::QUIC_DRAFT};
};

TEST_F(QuicClientTransportTest, ReadErrorCloseTransprot) {
  client->onReadError(folly::AsyncSocketException(
      folly::AsyncSocketException::INTERNAL_ERROR, "Where you wanna go", -1));
  EXPECT_FALSE(client->isClosed());
  client->onReadError(folly::AsyncSocketException(
      folly::AsyncSocketException::INTERNAL_ERROR,
      "He never saw it coming at all",
      -1));
  eventbase_->loopOnce();
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportTest, FirstPacketProcessedCallback) {
  client->addNewPeerAddress(serverAddr);
  client->start(&clientConnCallback);

  originalConnId = client->getConn().clientConnectionId;
  ServerConnectionIdParams params(0, 0, 0);
  client->getNonConstConn().serverConnectionId =
      *connIdAlgo_->encodeConnectionId(params);

  AckBlocks acks;
  acks.insert(0);
  auto& aead = getInitialCipher();
  auto& headerCipher = getInitialHeaderCipher();
  auto ackPacket = packetToBufCleartext(
      createAckPacket(
          client->getNonConstConn(),
          initialPacketNum,
          acks,
          PacketNumberSpace::Initial,
          &aead),
      aead,
      headerCipher,
      initialPacketNum);
  initialPacketNum++;
  EXPECT_CALL(clientConnCallback, onFirstPeerPacketProcessed()).Times(1);
  deliverData(serverAddr, ackPacket->coalesce());
  EXPECT_FALSE(client->hasWriteCipher());

  // Another ack won't trigger it again:
  auto oneMoreAckPacket = packetToBufCleartext(
      createAckPacket(
          client->getNonConstConn(),
          initialPacketNum,
          acks,
          PacketNumberSpace::Initial,
          &aead),
      aead,
      headerCipher,
      initialPacketNum);
  initialPacketNum++;
  EXPECT_CALL(clientConnCallback, onFirstPeerPacketProcessed()).Times(0);
  deliverData(serverAddr, oneMoreAckPacket->coalesce());
  EXPECT_FALSE(client->hasWriteCipher());

  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, CustomTransportParam) {
  EXPECT_TRUE(client->setCustomTransportParameter(
      std::make_unique<CustomIntegralTransportParameter>(
          kCustomTransportParameterThreshold, 0)));
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, CloseSocketOnWriteError) {
  client->addNewPeerAddress(serverAddr);
  EXPECT_CALL(*sock, write(_, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  client->start(&clientConnCallback);

  EXPECT_FALSE(client->isClosed());
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  eventbase_->loopOnce();
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportTest, AddNewPeerAddressSetsPacketSize) {
  folly::SocketAddress v4Address("0.0.0.0", 0);
  ASSERT_TRUE(v4Address.getFamily() == AF_INET);
  client->addNewPeerAddress(v4Address);
  EXPECT_EQ(kDefaultV4UDPSendPacketLen, client->getConn().udpSendPacketLen);

  folly::SocketAddress v6Address("::", 0);
  ASSERT_TRUE(v6Address.getFamily() == AF_INET6);
  client->addNewPeerAddress(v6Address);
  EXPECT_EQ(kDefaultV6UDPSendPacketLen, client->getConn().udpSendPacketLen);

  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, onNetworkSwitchNoReplace) {
  client->getNonConstConn().oneRttWriteCipher = test::createNoOpAead();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);
  client->setQLogger(mockQLogger);

  EXPECT_CALL(*mockQLogger, addConnectionMigrationUpdate(true)).Times(0);
  client->onNetworkSwitch(nullptr);
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, onNetworkSwitchReplaceAfterHandshake) {
  client->getNonConstConn().oneRttWriteCipher = test::createNoOpAead();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);
  client->setQLogger(mockQLogger);

  auto newSocket = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
      eventbase_.get());
  auto newSocketPtr = newSocket.get();
  EXPECT_CALL(*sock, pauseRead());
  EXPECT_CALL(*sock, close());
  EXPECT_CALL(*newSocketPtr, bind(_, _));
  EXPECT_CALL(*newSocketPtr, close());

  client->setQLogger(mockQLogger);
  EXPECT_CALL(*mockQLogger, addConnectionMigrationUpdate(true));
  client->onNetworkSwitch(std::move(newSocket));

  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, onNetworkSwitchReplaceNoHandshake) {
  auto newSocket = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
      eventbase_.get());
  auto newSocketPtr = newSocket.get();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);
  EXPECT_CALL(*mockQLogger, addConnectionMigrationUpdate(true)).Times(0);
  EXPECT_CALL(*newSocketPtr, bind(_, _)).Times(0);
  client->onNetworkSwitch(std::move(newSocket));
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, SocketClosedDuringOnTransportReady) {
  class ConnectionCallbackThatWritesOnTransportReady
      : public QuicSocket::ConnectionCallback {
   public:
    explicit ConnectionCallbackThatWritesOnTransportReady(
        std::shared_ptr<QuicSocket> socket)
        : socket_(std::move(socket)) {}

    void onTransportReady() noexcept override {
      socket_->close(folly::none);
      socket_.reset();
      onTransportReadyMock();
    }

    MOCK_METHOD(void, onFlowControlUpdate, (StreamId), (noexcept));
    MOCK_METHOD(void, onNewBidirectionalStream, (StreamId), (noexcept));
    MOCK_METHOD(void, onNewUnidirectionalStream, (StreamId), (noexcept));
    MOCK_METHOD(void, onStopSending, (StreamId, ApplicationErrorCode),
                (noexcept));
    MOCK_METHOD(void, onTransportReadyMock, (), (noexcept));
    MOCK_METHOD(void, onReplaySafe, (), (noexcept));
    MOCK_METHOD(void, onConnectionEnd, (), (noexcept));
    MOCK_METHOD(void, onConnectionError,
                ((std::pair<QuicErrorCode, std::string>)), (noexcept));

   private:
    std::shared_ptr<QuicSocket> socket_;
  };

  ConnectionCallbackThatWritesOnTransportReady callback(client);
  EXPECT_CALL(callback, onTransportReadyMock());
  EXPECT_CALL(callback, onReplaySafe()).Times(0);
  ON_CALL(*sock, write(_, _))
      .WillByDefault(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            socketWrites.push_back(buf->clone());
            return buf->computeChainDataLength();
          }));
  ON_CALL(*sock, address()).WillByDefault(ReturnRef(serverAddr));

  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  client->start(&callback);
  setConnectionIds();
  EXPECT_THROW(recvServerHello(), std::runtime_error);
}

TEST_F(QuicClientTransportTest, NetworkUnreachableIsFatalToConn) {
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  EXPECT_CALL(*sock, write(_, _)).WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
  client->start(&clientConnCallback);
  loopForWrites();
}

TEST_F(QuicClientTransportTest, HappyEyeballsWithSingleV4Address) {
  auto& conn = client->getConn();

  client->setHappyEyeballsEnabled(true);

  client->addNewPeerAddress(serverAddr);
  EXPECT_EQ(client->getConn().happyEyeballsState.v4PeerAddress, serverAddr);

  setupCryptoLayer();

  EXPECT_FALSE(conn.happyEyeballsState.finished);
  EXPECT_FALSE(conn.peerAddress.isInitialized());
  client->start(&clientConnCallback);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
  EXPECT_TRUE(conn.happyEyeballsState.finished);
  EXPECT_EQ(conn.peerAddress, serverAddr);
}

TEST_F(QuicClientTransportTest, HappyEyeballsWithSingleV6Address) {
  auto& conn = client->getConn();

  client->setHappyEyeballsEnabled(true);

  SocketAddress serverAddrV6{"::1", 443};
  client->addNewPeerAddress(serverAddrV6);
  EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, serverAddrV6);

  setupCryptoLayer();

  EXPECT_FALSE(conn.happyEyeballsState.finished);
  EXPECT_FALSE(conn.peerAddress.isInitialized());
  client->start(&clientConnCallback);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
  EXPECT_TRUE(conn.happyEyeballsState.finished);
  EXPECT_EQ(conn.peerAddress, serverAddrV6);
}

TEST_F(QuicClientTransportTest, IdleTimerResetOnWritingFirstData) {
  client->addNewPeerAddress(serverAddr);
  setupCryptoLayer();
  client->start(&clientConnCallback);
  loopForWrites();
  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportTest, SetQLoggerDcid) {
  client->setQLogger(nullptr);
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Client);

  EXPECT_CALL(
      *mockQLogger, setDcid(client->getConn().clientChosenDestConnectionId));
  client->setQLogger(mockQLogger);
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, CheckQLoggerRefCount) {
  auto mockQLogger1 = std::make_shared<MockQLogger>(VantagePoint::Client);
  auto mockQLogger2 = std::make_shared<MockQLogger>(VantagePoint::Client);
  EXPECT_CALL(
      *mockQLogger2, setDcid(client->getConn().clientChosenDestConnectionId))
      .Times(AtLeast(1));

  // no-op
  client->setQLogger(nullptr);
  CHECK(client->getQLogger() == nullptr);

  // set
  client->setQLogger(mockQLogger1);
  CHECK_EQ(client->getQLogger(), mockQLogger1);
  client->setQLogger(mockQLogger2);
  CHECK_EQ(client->getQLogger(), mockQLogger2);

  // mix set and unset
  client->setQLogger(nullptr);
  CHECK_EQ(client->getQLogger(), mockQLogger2);
  client->setQLogger(mockQLogger1);
  CHECK_EQ(client->getQLogger(), mockQLogger1);
  client->setQLogger(nullptr);
  CHECK_EQ(client->getQLogger(), mockQLogger1);

  // final unset
  client->setQLogger(nullptr);
  CHECK(client->getQLogger() == nullptr);

  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, SwitchServerCidsNoOtherIds) {
  auto originalCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{1, 2, 3, 4}), 2);
  auto& conn = client->getNonConstConn();
  conn.serverConnectionId = originalCid.connId;

  conn.peerConnectionIds.push_back(originalCid);
  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, SwitchServerCidsOneOtherCid) {
  auto originalCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{1, 2, 3, 4}), 1);
  auto secondCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{5, 6, 7, 8}), 2);

  auto& conn = client->getNonConstConn();
  conn.serverConnectionId = originalCid.connId;

  conn.peerConnectionIds.push_back(originalCid);
  conn.peerConnectionIds.push_back(secondCid);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 1);

  auto replacedCid = conn.serverConnectionId;
  EXPECT_NE(originalCid.connId, *replacedCid);
  EXPECT_EQ(secondCid.connId, *replacedCid);
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportTest, SwitchServerCidsMultipleCids) {
  auto originalCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{1, 2, 3, 4}), 1);
  auto secondCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{5, 6, 7, 8}), 2);
  auto thirdCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{3, 3, 3, 3}), 3);

  auto& conn = client->getNonConstConn();
  conn.serverConnectionId = originalCid.connId;

  conn.peerConnectionIds.push_back(originalCid);
  conn.peerConnectionIds.push_back(secondCid);
  conn.peerConnectionIds.push_back(thirdCid);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 1);

  // Uses the first unused connection id.
  auto replacedCid = conn.serverConnectionId;
  EXPECT_NE(originalCid.connId, *replacedCid);
  EXPECT_EQ(secondCid.connId, *replacedCid);
  client->closeNow(folly::none);
}

enum class ServerFirstPacketType : uint8_t { ServerHello, Retry };

class QuicClientTransportHappyEyeballsTest
    : public QuicClientTransportTest,
      public testing::WithParamInterface<ServerFirstPacketType> {
 public:
  void SetUpChild() override {
    auto secondSocket =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
            eventbase_.get());
    secondSock = secondSocket.get();

    client->setHappyEyeballsEnabled(true);
    client->addNewPeerAddress(serverAddrV4);
    client->addNewPeerAddress(serverAddrV6);
    client->addNewSocket(std::move(secondSocket));

    EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, serverAddrV6);
    EXPECT_EQ(client->getConn().happyEyeballsState.v4PeerAddress, serverAddrV4);

    setupCryptoLayer();
  }

 protected:
  void setupInitialDcidForRetry() {
    if (GetParam() == ServerFirstPacketType::Retry) {
      ConnectionId initialDstConnId(kInitialDstConnIdVecForRetryTest);
      client->getNonConstConn().originalDestinationConnectionId =
          initialDstConnId;
    }
  }

  void firstWinBeforeSecondStart(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    setupInitialDcidForRetry();
    auto firstPacketType = GetParam();
    EXPECT_CALL(*sock, write(firstAddress, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    setConnectionIds();

    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    EXPECT_FALSE(conn.happyEyeballsState.finished);
    if (firstPacketType == ServerFirstPacketType::ServerHello) {
      EXPECT_CALL(clientConnCallback, onTransportReady());
      EXPECT_CALL(clientConnCallback, onReplaySafe());
    }
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, pauseRead());
    EXPECT_CALL(*secondSock, close());
    if (firstPacketType == ServerFirstPacketType::Retry) {
      recvServerRetry(firstAddress);
    } else {
      performFakeHandshake(firstAddress);
    }
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_TRUE(client->getConn().happyEyeballsState.finished);
    EXPECT_EQ(client->getConn().originalPeerAddress, firstAddress);
    EXPECT_EQ(client->getConn().peerAddress, firstAddress);
  }

  void firstWinAfterSecondStart(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    auto firstPacketType = GetParam();
    setupInitialDcidForRetry();

    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    setConnectionIds();

    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(Invoke([&](const SocketAddress&,
                             const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();
    EXPECT_FALSE(conn.happyEyeballsState.finished);
    if (firstPacketType == ServerFirstPacketType::ServerHello) {
      EXPECT_CALL(clientConnCallback, onTransportReady());
      EXPECT_CALL(clientConnCallback, onReplaySafe());
    }
    EXPECT_CALL(*sock, write(firstAddress, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, pauseRead());
    EXPECT_CALL(*secondSock, close());
    if (firstPacketType == ServerFirstPacketType::Retry) {
      recvServerRetry(firstAddress);
    } else {
      performFakeHandshake(firstAddress);
    }
    EXPECT_TRUE(client->getConn().happyEyeballsState.finished);
    EXPECT_FALSE(
        client->getConn().happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_EQ(client->getConn().originalPeerAddress, firstAddress);
    EXPECT_EQ(client->getConn().peerAddress, firstAddress);
  }

  void secondWin(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    auto firstPacketType = GetParam();
    setupInitialDcidForRetry();

    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    setConnectionIds();
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_EQ(socketWrites.size(), 1);

    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(Invoke([&](const SocketAddress&,
                             const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));

    socketWrites.clear();

    EXPECT_FALSE(conn.happyEyeballsState.finished);
    if (firstPacketType == ServerFirstPacketType::ServerHello) {
      EXPECT_CALL(clientConnCallback, onTransportReady());
      EXPECT_CALL(clientConnCallback, onReplaySafe());
    }
    EXPECT_CALL(*sock, write(_, _)).Times(0);
    EXPECT_CALL(*sock, pauseRead());
    EXPECT_CALL(*sock, close());
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    if (firstPacketType == ServerFirstPacketType::Retry) {
      recvServerRetry(secondAddress);
    } else {
      performFakeHandshake(secondAddress);
    }
    EXPECT_TRUE(client->getConn().happyEyeballsState.finished);
    EXPECT_FALSE(
        client->getConn().happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_EQ(client->getConn().originalPeerAddress, secondAddress);
    EXPECT_EQ(client->getConn().peerAddress, secondAddress);
  }

  void secondBindFailure(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    setupInitialDcidForRetry();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, bind(_, _))
        .WillOnce(Invoke(
            [](const folly::SocketAddress&, auto) { throw std::exception(); }));
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_TRUE(conn.happyEyeballsState.finished);
  }

  void nonFatalWriteErrorOnFirstBeforeSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    TransportSettings settings;
    client->setTransportSettings(settings);
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(_, _));
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    // Continue trying first socket
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnFirstBeforeSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    EXPECT_CALL(*secondSock, write(_, _));
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    // Give up first socket
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    EXPECT_CALL(*sock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnFirstAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _)).Times(2);
    EXPECT_CALL(*secondSock, write(secondAddress, _)).Times(2);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnFirstAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*sock, pauseRead()).Times(2);
    EXPECT_CALL(*sock, close()).Times(1);
    EXPECT_CALL(*secondSock, write(secondAddress, _));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(_, _)).Times(0);
    EXPECT_CALL(*secondSock, write(secondAddress, _)).Times(2);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnSecondAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _)).Times(2);
    EXPECT_CALL(*secondSock, write(secondAddress, _)).Times(2);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnSecondAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    // Socket is paused read once during happy eyeballs
    // Socket is paused read for the second time when QuicClientTransport dies
    EXPECT_CALL(*secondSock, pauseRead()).Times(2);
    EXPECT_CALL(*secondSock, close()).Times(1);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _)).Times(2);
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void nonFatalWriteErrorOnBothAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EAGAIN, -1));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);

    EXPECT_CALL(*sock, write(firstAddress, _)).Times(2);
    EXPECT_CALL(*secondSock, write(secondAddress, _)).Times(2);
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();
  }

  void fatalWriteErrorOnBothAfterSecondStarts(
      const SocketAddress& firstAddress,
      const SocketAddress& secondAddress) {
    auto& conn = client->getConn();

    EXPECT_CALL(*sock, write(firstAddress, _));
    EXPECT_CALL(*secondSock, write(_, _)).Times(0);
    client->start(&clientConnCallback);
    EXPECT_EQ(conn.peerAddress, firstAddress);
    EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
    EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire conn attempt timeout
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();
    client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
    EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
    EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());

    // Manually expire loss timeout to trigger write to both first and second
    // socket
    EXPECT_CALL(*sock, write(firstAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    EXPECT_CALL(*secondSock, write(secondAddress, _))
        .WillOnce(SetErrnoAndReturn(EBADF, -1));
    EXPECT_CALL(clientConnCallback, onConnectionError(_));
    client->lossTimeout().cancelTimeout();
    client->lossTimeout().timeoutExpired();

    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToFirstSocket);
    EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  }

 protected:
  folly::test::MockAsyncUDPSocket* secondSock;
  SocketAddress serverAddrV4{"127.0.0.1", 443};
  SocketAddress serverAddrV6{"::1", 443};
};

INSTANTIATE_TEST_CASE_P(
    QuicClientTransportHappyEyeballsTests,
    QuicClientTransportHappyEyeballsTest,
    ::testing::Values(
        ServerFirstPacketType::ServerHello,
        ServerFirstPacketType::Retry));

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV6WinBeforeV4Start) {
  firstWinBeforeSecondStart(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV6WinAfterV4Start) {
  firstWinAfterSecondStart(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV4Win) {
  secondWin(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V6FirstAndV4BindFailure) {
  secondBindFailure(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6NonFatalErrorBeforeV4Starts) {
  nonFatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6FatalErrorBeforeV4Start) {
  fatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6NonFatalErrorAfterV4Starts) {
  nonFatalWriteErrorOnFirstAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV6FatalErrorAfterV4Start) {
  fatalWriteErrorOnFirstAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV4NonFatalErrorAfterV4Start) {
  nonFatalWriteErrorOnSecondAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndV4FatalErrorAfterV4Start) {
  fatalWriteErrorOnSecondAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndBothNonFatalErrorAfterV4Start) {
  nonFatalWriteErrorOnBothAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_F(
    QuicClientTransportHappyEyeballsTest,
    V6FirstAndBothFatalErrorAfterV4Start) {
  fatalWriteErrorOnBothAfterSecondStarts(serverAddrV6, serverAddrV4);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV4WinBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  firstWinBeforeSecondStart(serverAddrV4, serverAddrV6);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV4WinAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  firstWinAfterSecondStart(serverAddrV4, serverAddrV6);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV6Win) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  secondWin(serverAddrV4, serverAddrV6);
}

TEST_P(QuicClientTransportHappyEyeballsTest, V4FirstAndV6BindFailure) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  secondBindFailure(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4NonFatalErrorBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4FatalErrorBeforeV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnFirstBeforeSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4NonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnFirstAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV4FatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnFirstAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV6NonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnSecondAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndV6FatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnSecondAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndBothNonFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  nonFatalWriteErrorOnBothAfterSecondStarts(serverAddrV4, serverAddrV6);
}

TEST_P(
    QuicClientTransportHappyEyeballsTest,
    V4FirstAndBothFatalErrorAfterV6Start) {
  client->setHappyEyeballsCachedFamily(AF_INET);
  fatalWriteErrorOnBothAfterSecondStarts(serverAddrV4, serverAddrV6);
}

class QuicClientTransportAfterStartTestBase : public QuicClientTransportTest {
 public:
  void SetUpChild() override {
    client->addNewPeerAddress(serverAddr);
    client->setHostname(hostname_);
    client->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    ON_CALL(*sock, write(_, _))
        .WillByDefault(Invoke([&](const SocketAddress&,
                                  const std::unique_ptr<folly::IOBuf>& buf) {
          socketWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    ON_CALL(*sock, address()).WillByDefault(ReturnRef(serverAddr));

    setupCryptoLayer();
    start();
    client->getNonConstConn().streamManager->setMaxLocalBidirectionalStreams(
        std::numeric_limits<uint32_t>::max());
    client->getNonConstConn().streamManager->setMaxLocalUnidirectionalStreams(
        std::numeric_limits<uint32_t>::max());
  }

 protected:
  std::string hostname_{"TestHost"};
};

class QuicClientTransportAfterStartTest
    : public QuicClientTransportAfterStartTestBase,
      public testing::WithParamInterface<uint8_t> {};

INSTANTIATE_TEST_CASE_P(
    QuicClientZeroLenConnIds,
    QuicClientTransportAfterStartTest,
    ::Values(0, 8));

class QuicClientTransportVersionAndRetryTest
    : public QuicClientTransportAfterStartTestBase {
 public:
  ~QuicClientTransportVersionAndRetryTest() override = default;

  void start() override {
    client->start(&clientConnCallback);
    originalConnId = client->getConn().clientConnectionId;
    // create server chosen connId with processId = 0 and workerId = 0
    ServerConnectionIdParams params(0, 0, 0);
    serverChosenConnId = *connIdAlgo_->encodeConnectionId(params);
    // The tests that we do here create streams before crypto is finished,
    // so we initialize the peer streams, to allow for this behavior. TODO: when
    // 0-rtt support exists, remove this.
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    client->getNonConstConn()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    client->getNonConstConn().flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
  }
};

class QuicClientVersionParamInvalidTest
    : public QuicClientTransportAfterStartTestBase {
 public:
  ~QuicClientVersionParamInvalidTest() override = default;

  void start() override {
    // force the server to declare that the version negotiated was invalid.;
    mockClientHandshake->negotiatedVersion = MVFST2;

    client->start(&clientConnCallback);
    originalConnId = client->getConn().clientConnectionId;
  }
};

TEST_F(QuicClientTransportAfterStartTest, ReadStream) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
    EXPECT_TRUE(folly::IOBufEqualTo()((*readData).first, expected));
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, CleanupReadLoopCounting) {
  auto streamId = client->createBidirectionalStream().value();
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
  conn.readDebugState.loopCount = 20;

  auto data = IOBuf::copyBuffer("Short Trip Home");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  EXPECT_EQ(NoReadReason::READ_OK, conn.readDebugState.noReadReason);
  EXPECT_EQ(0, conn.readDebugState.loopCount);
}

TEST_F(QuicClientTransportAfterStartTest, StaleReadLoopCounting) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  auto data = IOBuf::copyBuffer("Short Trip Home");
  deliverData(data->coalesce());
  EXPECT_EQ(NoReadReason::STALE_DATA, conn.readDebugState.noReadReason);
}

TEST_F(QuicClientTransportAfterStartTest, TruncatedReadLoopCounting) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(1, NoReadReason::TRUNCATED));
  client->invokeOnDataAvailable(serverAddr, 1000, true);
}

TEST_F(QuicClientTransportAfterStartTest, RetriableErrorLoopCounting) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.transportSettings.maxRecvBatchSize = 1;
  // Empty socketReads will lead to EAGAIN in mock setup.
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(1, NoReadReason::RETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, ReadLoopTwice) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.transportSettings.maxRecvBatchSize = 1;
  socketReads.emplace_back(TestReadData(EBADF));
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(1, NoReadReason::NONRETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);
  socketReads.clear();

  socketReads.emplace_back(TestReadData(EBADF));
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(2, NoReadReason::NONRETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, NonretriableErrorLoopCounting) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.transportSettings.maxRecvBatchSize = 1;
  socketReads.emplace_back(TestReadData(EBADF));
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(1, NoReadReason::NONRETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, PartialReadLoopCounting) {
  auto streamId = client->createBidirectionalStream().value();
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  auto data = IOBuf::copyBuffer("Short Trip Home");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Read twice in the loop, once success, then fail. Loop detector shouldn't
  // fire.
  conn.transportSettings.maxRecvBatchSize = 2;
  socketReads.emplace_back(TestReadData(packet->coalesce(), serverAddr));
  socketReads.emplace_back(TestReadData(EBADF));
  EXPECT_CALL(*rawLoopDetectorCallback, onSuspiciousReadLoops(_, _)).Times(0);
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, ReadLoopCountingRecvmmsg) {
  auto& conn = client->getNonConstConn();
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);

  conn.transportSettings.shouldUseRecvmmsgForBatchRecv = true;
  conn.transportSettings.maxRecvBatchSize = 1;
  EXPECT_CALL(*sock, recvmmsg(_, 1, _, nullptr))
      .WillOnce(Invoke(
          [](struct mmsghdr*, unsigned int, unsigned int, struct timespec*) {
            errno = EAGAIN;
            return -1;
          }));
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(1, NoReadReason::RETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);

  EXPECT_CALL(*sock, recvmmsg(_, 1, _, nullptr))
      .WillOnce(Invoke(
          [](struct mmsghdr*, unsigned int, unsigned int, struct timespec*) {
            errno = EBADF;
            return -1;
          }));
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousReadLoops(2, NoReadReason::NONRETRIABLE_ERROR));
  client->invokeOnNotifyDataAvailable(*sock);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamMultiplePackets) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto data = IOBuf::copyBuffer("hello");

  auto expected = data->clone();
  expected->prependChain(data->clone());
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data="
              << copy->clone()->moveToFbString().toStdString()
              << " on stream=" << streamId;
    EXPECT_EQ(
        copy->moveToFbString().toStdString(),
        expected->clone()->moveToFbString().toStdString());
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet1 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none /* longHeaderOverride */,
      false /* eof */));
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none /* longHeaderOverride */,
      true /* eof */,
      folly::none /* shortHeaderOverride */,
      data->length() /* offset */));

  socketReads.emplace_back(TestReadData(packet1->coalesce(), serverAddr));
  deliverData(packet2->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamWithRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  EXPECT_CALL(readCb, readError(_, _)).Times(0);
  deliverNetworkError(EAGAIN);
  client->setReadCallback(streamId, nullptr);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamWithNonRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  // TODO: we currently do not close the socket, but maybe we can in the future.
  EXPECT_CALL(readCb, readError(_, _)).Times(0);
  deliverNetworkError(EBADF);
  client->setReadCallback(streamId, nullptr);
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReadStreamMultiplePacketsWithRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
    EXPECT_TRUE(folly::IOBufEqualTo()((*readData).first, expected));
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  socketReads.emplace_back(TestReadData(packet->coalesce(), serverAddr));
  deliverNetworkError(EAGAIN);
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReadStreamMultiplePacketsWithNonRetriableError) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).Times(0);

  // TODO: we currently do not close the socket, but maybe we can in the future.
  EXPECT_CALL(readCb, readError(_, _)).Times(0);
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  {
    EXPECT_CALL(*sock, pauseRead()).Times(AtLeast(1));
    socketReads.emplace_back(TestReadData(packet->coalesce(), serverAddr));
    deliverNetworkError(EBADF);
  }
  client->setReadCallback(streamId, nullptr);
}

TEST_F(QuicClientTransportAfterStartTest, RecvNewConnectionIdValid) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  auto token = StatelessResetToken{1, 9, 2, 0};
  NewConnectionIdFrame newConnId(1, 0, ConnectionId({2, 4, 2, 3}), token);
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_EQ(conn.peerConnectionIds[1].connId, newConnId.connectionId);
  EXPECT_EQ(conn.peerConnectionIds[1].sequenceNumber, newConnId.sequenceNumber);
  EXPECT_EQ(conn.peerConnectionIds[1].token, newConnId.token);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RecvNewConnectionIdTooManyReceivedIds) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 0;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicClientTransportAfterStartTest, RecvNewConnectionIdInvalidRetire) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1, 3, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  EXPECT_THROW(deliverData(data->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, RecvNewConnectionIdUsing0LenCid) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 2;

  conn.serverConnectionId = ConnectionId(std::vector<uint8_t>{});
  conn.peerConnectionIds.pop_back();
  conn.peerConnectionIds.emplace_back(*conn.serverConnectionId, 0);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  try {
    deliverData(data->coalesce(), false);
    FAIL();
  } catch (const std::runtime_error& e) {
    EXPECT_EQ(std::string(e.what()), "Protocol violation");
  }
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RecvNewConnectionIdNoopValidDuplicate) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ConnectionId connId2({5, 5, 5, 5});
  conn.peerConnectionIds.emplace_back(connId2, 1);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(1, 0, connId2, StatelessResetToken());
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  deliverData(data->coalesce(), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RecvNewConnectionIdExceptionInvalidDuplicate) {
  auto& conn = client->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 1;

  ConnectionId connId2({5, 5, 5, 5});
  conn.peerConnectionIds.emplace_back(connId2, 1);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(2, 0, connId2, StatelessResetToken());
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_THROW(deliverData(data->coalesce()), std::runtime_error);
}

TEST_P(QuicClientTransportAfterStartTest, ReadStreamCoalesced) {
  expectQuicStatsPacketDrop(
      QuicTransportStatsCallback::PacketDropReason::PARSE_ERROR);
  uint8_t connIdSize = GetParam();

  client->getNonConstConn().clientConnectionId =
      ConnectionId(std::vector<uint8_t>(connIdSize, 1));
  setConnectionIds();

  StreamId streamId = client->createBidirectionalStream().value();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;

  client->setReadCallback(streamId, &readCb);
  bool dataDelivered = false;
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 1000);
    auto copy = readData->first->clone();
    LOG(INFO) << "Client received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
    EXPECT_TRUE(folly::IOBufEqualTo()((*readData).first, expected));
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));

  FizzCryptoFactory cryptoFactory;
  auto garbage = IOBuf::copyBuffer("garbage");
  auto initialCipher = cryptoFactory.getServerInitialCipher(
      *serverChosenConnId, QuicVersion::MVFST);
  auto firstPacketNum = appDataPacketNum++;
  auto packet1 = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          firstPacketNum,
          streamId,
          *garbage,
          initialCipher->getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      *initialCipher,
      getInitialHeaderCipher(),
      firstPacketNum);
  packet1->coalesce();
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      firstPacketNum,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  packet1->appendChain(std::move(packet2));
  deliverData(packet1->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  client->close(folly::none);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 65 + (2 * connIdSize));
  EXPECT_EQ(event->dropReason, kParse);
}

TEST_F(QuicClientTransportAfterStartTest, ReadStreamCoalescedMany) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);
  auto expected = IOBuf::copyBuffer("hello");
  EXPECT_CALL(readCb, readAvailable(streamId)).Times(0);
  FizzCryptoFactory cryptoFactory;
  BufQueue packets;
  for (int i = 0; i < kMaxNumCoalescedPackets; i++) {
    auto garbage = IOBuf::copyBuffer("garbage");
    auto initialCipher = cryptoFactory.getServerInitialCipher(
        *serverChosenConnId, QuicVersion::MVFST);
    auto packetNum = appDataPacketNum++;
    auto packet1 = packetToBufCleartext(
        createStreamPacket(
            *serverChosenConnId /* src */,
            *originalConnId /* dest */,
            packetNum,
            streamId,
            *garbage,
            initialCipher->getCipherOverhead(),
            0 /* largestAcked */,
            std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
        *initialCipher,
        getInitialHeaderCipher(),
        packetNum);
    packets.append(std::move(packet1));
  }
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  packets.append(std::move(packet2));
  auto data = packets.move();
  deliverData(data->coalesce());
  eventbase_->loopOnce();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, RecvPathChallengeNoAvailablePeerIds) {
  auto& conn = client->getNonConstConn();

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  PathChallengeFrame pathChallenge(123);
  ASSERT_TRUE(builder.canBuildPacket());
  writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  EXPECT_THROW(deliverData(data->coalesce(), false), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, RecvPathChallengeAvailablePeerId) {
  auto& conn = client->getNonConstConn();
  auto originalCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{1, 2, 3, 4}), 1);
  auto secondCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{5, 6, 7, 8}), 2);

  conn.serverConnectionId = originalCid.connId;

  conn.peerConnectionIds.push_back(originalCid);
  conn.peerConnectionIds.push_back(secondCid);

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  PathChallengeFrame pathChallenge(123);
  ASSERT_TRUE(builder.canBuildPacket());
  writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder);

  auto packet = std::move(builder).buildPacket();
  auto data = packetToBuf(packet);

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  deliverData(data->coalesce(), false);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 2);

  // The RetireConnectionId frame will be enqueued before the PathResponse.
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 1);

  PathResponseFrame& pathResponse =
      *conn.pendingEvents.frames[1].asPathResponseFrame();
  EXPECT_EQ(pathResponse.pathData, pathChallenge.pathData);
}

bool verifyFramePresent(
    std::vector<std::unique_ptr<folly::IOBuf>>& socketWrites,
    QuicReadCodec& readCodec,
    QuicFrame::Type frameType) {
  AckStates ackStates;
  for (auto& write : socketWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = readCodec.parsePacket(packetQueue, ackStates);
    auto regularPacket = result.regularPacket();
    if (!regularPacket) {
      continue;
    }
    for (FOLLY_MAYBE_UNUSED auto& frame : regularPacket->frames) {
      if (frame.type() != frameType) {
        continue;
      }
      return true;
    }
  }
  return false;
}

TEST_F(QuicClientTransportAfterStartTest, CloseConnectionWithStreamPending) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);
  loopForWrites();
  // ack all the packets
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::AppData)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 client->getNonConstConn(), PacketNumberSpace::AppData)
                 ->packet.header.getPacketSequenceNum();
  acks.insert(start, end);

  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      acks,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  socketWrites.clear();

  auto serverReadCodec = makeEncryptedCodec();
  EXPECT_CALL(readCb, readError(streamId, _));
  client->closeGracefully();
  EXPECT_FALSE(verifyFramePresent(
      socketWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));

  // close the stream
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  socketWrites.clear();
  deliverData(packet->coalesce());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::ConnectionClose, qLogger);
  // expecting that connection close called twice
  EXPECT_EQ(indices.size(), 2);

  // event called in closeGracefully()
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogConnectionCloseEvent*>(tmp.get());
  EXPECT_EQ(event->error, kNoError);
  EXPECT_EQ(event->reason, kGracefulExit);
  EXPECT_TRUE(event->drainConnection);
  EXPECT_FALSE(event->sendCloseImmediately);

  // event called in closeImpl(), right before transport is closed
  auto tmp2 = std::move(qLogger->logs[indices[1]]);
  auto event2 = dynamic_cast<QLogConnectionCloseEvent*>(tmp2.get());
  EXPECT_EQ(event2->error, kNoError);
  auto reason = folly::to<std::string>(
      "Server: ", kNoError, ", Peer: isReset: ", 0, ", Peer: isAbandon: ", 0);
  EXPECT_EQ(event2->reason, reason);
  EXPECT_TRUE(event2->drainConnection);
  EXPECT_TRUE(event2->sendCloseImmediately);
}

TEST_F(QuicClientTransportAfterStartTest, CloseConnectionWithNoStreamPending) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);

  loopForWrites();

  // ack all the packets
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::AppData)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 client->getNonConstConn(), PacketNumberSpace::AppData)
                 ->packet.header.getPacketSequenceNum();
  acks.insert(start, end);

  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      acks,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  socketWrites.clear();

  // close the stream
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  socketWrites.clear();
  deliverData(packet->coalesce());
  EXPECT_CALL(readCb, readError(streamId, _));
  client->close(folly::none);
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

class QuicClientTransportAfterStartTestClose
    : public QuicClientTransportAfterStartTestBase,
      public testing::WithParamInterface<bool> {};

INSTANTIATE_TEST_CASE_P(
    QuicClientTransportAfterStartTestCloseWithError,
    QuicClientTransportAfterStartTestClose,
    Values(true, false));

TEST_P(
    QuicClientTransportAfterStartTestClose,
    CloseConnectionWithErrorCleartext) {
  StreamId streamId = client->createBidirectionalStream().value();
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);

  loopForWrites();
  socketWrites.clear();
  EXPECT_CALL(readCb, readError(streamId, _));
  if (GetParam()) {
    client->close(std::make_pair(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("stopping")));
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));

    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::ConnectionClose, qLogger);
    // expecting that connection close called once
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogConnectionCloseEvent*>(tmp.get());
    EXPECT_EQ(event->error, "stopping");
    EXPECT_EQ(event->reason, "stopping");
    EXPECT_TRUE(event->drainConnection);
    EXPECT_TRUE(event->sendCloseImmediately);

  } else {
    client->close(folly::none);
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::ConnectionClose, qLogger);
    // expecting that connection close called once
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogConnectionCloseEvent*>(tmp.get());
    EXPECT_EQ(event->error, "No Error");
    EXPECT_EQ(event->reason, "No Error");
    EXPECT_TRUE(event->drainConnection);
    EXPECT_TRUE(event->sendCloseImmediately);
  }
}

TEST_F(QuicClientTransportAfterStartTest, RecvPostHandshakeData) {
  auto oneRttReadOffset =
      client->getConn().cryptoState->oneRttStream.currentReadOffset;
  recvTicket();
  EXPECT_GT(
      client->getConn().cryptoState->oneRttStream.currentReadOffset,
      oneRttReadOffset);
}

TEST_F(QuicClientTransportAfterStartTest, RecvRetransmittedHandshakeData) {
  recvTicket();
  auto oneRttReadOffset =
      client->getConn().cryptoState->oneRttStream.currentReadOffset;
  // Simulate retransmission of the same ticket.
  recvTicket(0);
  EXPECT_EQ(
      client->getConn().cryptoState->oneRttStream.currentReadOffset,
      oneRttReadOffset);
}

TEST_F(QuicClientTransportAfterStartTest, RecvAckOfCryptoStream) {
  // Simulate ack from server
  auto& cryptoState = client->getConn().cryptoState;
  EXPECT_GT(cryptoState->initialStream.retransmissionBuffer.size(), 0);
  EXPECT_GT(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
  EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);

  auto& aead = getInitialCipher();
  auto& headerCipher = getInitialHeaderCipher();
  // initial
  {
    AckBlocks acks;
    auto start = getFirstOutstandingPacket(
                     client->getNonConstConn(), PacketNumberSpace::Initial)
                     ->packet.header.getPacketSequenceNum();
    auto end = getLastOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::Initial)
                   ->packet.header.getPacketSequenceNum();
    acks.insert(start, end);
    auto pn = initialPacketNum++;
    auto ackPkt = createAckPacket(
        client->getNonConstConn(), pn, acks, PacketNumberSpace::Initial, &aead);
    deliverData(
        packetToBufCleartext(ackPkt, aead, headerCipher, pn)->coalesce());
    EXPECT_EQ(cryptoState->initialStream.retransmissionBuffer.size(), 0);
    EXPECT_GT(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);
  }
  // handshake
  {
    AckBlocks acks;
    auto start = getFirstOutstandingPacket(
                     client->getNonConstConn(), PacketNumberSpace::Handshake)
                     ->packet.header.getPacketSequenceNum();
    auto end = getLastOutstandingPacket(
                   client->getNonConstConn(), PacketNumberSpace::Handshake)
                   ->packet.header.getPacketSequenceNum();
    acks.insert(start, end);
    auto pn = handshakePacketNum++;
    auto ackPkt = createAckPacket(
        client->getNonConstConn(), pn, acks, PacketNumberSpace::Handshake);
    deliverData(packetToBuf(ackPkt)->coalesce());
    EXPECT_EQ(cryptoState->initialStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);
  }
}

TEST_F(QuicClientTransportAfterStartTest, RecvOneRttAck) {
  EXPECT_GT(
      client->getConn().cryptoState->initialStream.retransmissionBuffer.size(),
      0);
  EXPECT_GT(
      client->getConn()
          .cryptoState->handshakeStream.retransmissionBuffer.size(),
      0);

  // Client doesn't send one rtt crypto data today
  EXPECT_EQ(
      client->getConn().cryptoState->oneRttStream.retransmissionBuffer.size(),
      0);
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);
  loopForWrites();

  AckBlocks sentPackets;
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());

  // Should have canceled retransmissions
  EXPECT_EQ(
      client->getConn().cryptoState->initialStream.retransmissionBuffer.size(),
      0);
  EXPECT_EQ(
      client->getConn()
          .cryptoState->handshakeStream.retransmissionBuffer.size(),
      0);
}

TEST_P(QuicClientTransportAfterStartTestClose, CloseConnectionWithError) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  client->setReadCallback(streamId, &readCb);
  client->writeChain(streamId, expected->clone(), true, false);
  loopForWrites();
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  deliverData(packet->coalesce());
  socketWrites.clear();
  if (GetParam()) {
    client->close(std::make_pair(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("stopping")));
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
  } else {
    client->close(folly::none);
    EXPECT_TRUE(verifyFramePresent(
        socketWrites,
        *makeHandshakeCodec(),
        QuicFrame::Type::ConnectionCloseFrame));
  }
}

class QuicClientTransportAfterStartTestTimeout
    : public QuicClientTransportAfterStartTestBase,
      public testing::WithParamInterface<QuicVersion> {};

INSTANTIATE_TEST_CASE_P(
    QuicClientTransportAfterStartTestTimeouts,
    QuicClientTransportAfterStartTestTimeout,
    Values(
        QuicVersion::MVFST,
        QuicVersion::MVFST_D24,
        QuicVersion::QUIC_DRAFT));

TEST_P(
    QuicClientTransportAfterStartTestTimeout,
    HandshakeCipherTimeoutAfterFirstData) {
  client->getNonConstConn().version = GetParam();
  StreamId streamId = client->createBidirectionalStream().value();

  EXPECT_NE(client->getConn().readCodec->getInitialCipher(), nullptr);
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      true));
  deliverData(packet->coalesce());
  EXPECT_NE(client->getConn().readCodec->getInitialCipher(), nullptr);
  if (GetParam() == QuicVersion::MVFST_D24) {
    EXPECT_TRUE(
        client->getConn().readCodec->getHandshakeDoneTime().has_value());
  } else {
    EXPECT_FALSE(
        client->getConn().readCodec->getHandshakeDoneTime().has_value());
  }
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerResetOnRecvNewData) {
  // spend some time looping the evb
  for (int i = 0; i < 10; ++i) {
    eventbase_->loopOnce(EVLOOP_NONBLOCK);
  }
  StreamId streamId = client->createBidirectionalStream().value();
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  deliverData(packet->coalesce());
  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());

  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  deliverData(packet2->coalesce());
  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerNotResetOnDuplicatePacket) {
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Writes may cause idle timer to be set, so don't loop for a write.
  deliverData(packet->coalesce(), false);

  ASSERT_TRUE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_TRUE(client->idleTimeout().isScheduled());

  client->idleTimeout().cancelTimeout();
  client->getNonConstConn().receivedNewPacketBeforeWrite = false;
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  // Try delivering the same packet again
  deliverData(packet->coalesce(), false);

  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  client->closeNow(folly::none);
}

TEST_P(QuicClientTransportAfterStartTestClose, TimeoutsNotSetAfterClose) {
  expectQuicStatsPacketDrop(
      QuicTransportStatsCallback::PacketDropReason::CLIENT_STATE_CLOSED);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  if (GetParam()) {
    client->close(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("how about no")));
  } else {
    client->close(folly::none);
  }
  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());

  deliverDataWithoutErrorCheck(packet->coalesce());
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  ASSERT_FALSE(client->lossTimeout().isScheduled());
  ASSERT_FALSE(client->ackTimeout().isScheduled());
  ASSERT_TRUE(client->drainTimeout().isScheduled());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 0);
  EXPECT_EQ(event->dropReason, kAlreadyClosed);
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerNotResetOnWritingOldData) {
  StreamId streamId = client->createBidirectionalStream().value();

  // There should still be outstanding packets
  auto expected = IOBuf::copyBuffer("hello");
  client->idleTimeout().cancelTimeout();
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  client->writeChain(streamId, expected->clone(), false, false);
  loopForWrites();

  ASSERT_FALSE(client->getConn().receivedNewPacketBeforeWrite);
  ASSERT_FALSE(client->idleTimeout().isScheduled());
  client->closeNow(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimerResetNoOutstandingPackets) {
  // This will clear out all the outstanding packets
  AckBlocks sentPackets;
  for (auto& packet : client->getNonConstConn().outstandings.packets) {
    auto packetNum = packet.packet.header.getPacketSequenceNum();
    sentPackets.insert(packetNum);
  }
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());

  // Clear out all the outstanding packets to simulate quiescent state.
  client->getNonConstConn().receivedNewPacketBeforeWrite = false;
  client->getNonConstConn().outstandings.packets.clear();
  client->getNonConstConn().outstandings.handshakePacketsCount = 0;
  client->getNonConstConn().outstandings.clonedPacketsCount = 0;
  client->idleTimeout().cancelTimeout();
  auto streamId = client->createBidirectionalStream().value();
  auto expected = folly::IOBuf::copyBuffer("hello");
  client->writeChain(streamId, expected->clone(), false, false);
  loopForWrites();
  ASSERT_TRUE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, IdleTimeoutExpired) {
  EXPECT_CALL(*sock, close());
  socketWrites.clear();
  client->idleTimeout().timeoutExpired();

  EXPECT_FALSE(client->idleTimeout().isScheduled());
  EXPECT_TRUE(client->isDraining());
  EXPECT_TRUE(client->isClosed());

  auto serverCodec = makeEncryptedCodec();
  // We expect a conn close in a cleartext packet.
  EXPECT_FALSE(verifyFramePresent(
      socketWrites, *serverCodec, QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_FALSE(verifyFramePresent(
      socketWrites, *serverCodec, QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_TRUE(socketWrites.empty());
}

TEST_F(QuicClientTransportAfterStartTest, RecvDataAfterIdleTimeout) {
  expectQuicStatsPacketDrop(
      QuicTransportStatsCallback::PacketDropReason::CLIENT_STATE_CLOSED);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  EXPECT_CALL(*sock, close());
  client->idleTimeout().timeoutExpired();

  socketWrites.clear();
  StreamId streamId = 11;
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeEncryptedCodec(true),
      QuicFrame::Type::ConnectionCloseFrame));
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 0);
  EXPECT_EQ(event->dropReason, kAlreadyClosed);
}

TEST_F(QuicClientTransportAfterStartTest, InvalidStream) {
  StreamId streamId = 10;
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportAfterStartTest, WrongCleartextCipher) {
  FizzCryptoFactory cryptoFactory;
  StreamId streamId = client->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  // Test sending packet with wrong connection id, should drop it, it normally
  // throws on getting unencrypted stream data.
  PacketNum nextPacketNum = appDataPacketNum++;

  auto initialCipher = cryptoFactory.getServerInitialCipher(
      *serverChosenConnId, QuicVersion::MVFST);
  auto packet = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          nextPacketNum,
          streamId,
          *expected,
          initialCipher->getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      *initialCipher,
      getInitialHeaderCipher(),
      nextPacketNum);
  deliverData(packet->coalesce());
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReceiveRstStreamNonExistentClientStream) {
  StreamId streamId = 0x04;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(rstFrame, builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    ReceiveRstStreamNonExistentAndOtherFrame) {
  StreamId serverUnidirectional = 0x03;

  // Deliver reset on peer unidirectional stream to close the stream.
  RstStreamFrame rstFrame(
      serverUnidirectional, GenericApplicationErrorCode::UNKNOWN, 0);
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  writeFrame(rstFrame, builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet->coalesce());

  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  ShortHeader header2(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder2.encodePacketHeader();
  writeFrame(rstFrame, builder2);

  auto data = folly::IOBuf::copyBuffer("hello");
  writeStreamFrameHeader(
      builder2,
      streamId,
      0,
      data->computeChainDataLength(),
      data->computeChainDataLength(),
      false,
      folly::none /* skipLenHint */);
  writeStreamFrameData(builder2, data->clone(), data->computeChainDataLength());
  auto packetObject = std::move(builder2).buildPacket();
  auto packet2 = packetToBuf(std::move(packetObject));
  deliverData(packet2->coalesce());

  auto readData = client->read(streamId, 0);
  ASSERT_TRUE(readData.hasValue());
  ASSERT_NE(readData.value().first, nullptr);
  EXPECT_TRUE(folly::IOBufEqualTo()(*readData.value().first, *data));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveRstStreamAfterEom) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto id) {
    auto readData = client->read(id, 0);
    EXPECT_TRUE(readData->second);
  }));

  // delivers the eof
  auto data = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());

  EXPECT_CALL(readCb, readError(streamId, _));

  RstStreamFrame rstFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN, data->length());
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(rstFrame, builder);
  auto packet2 = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet2->coalesce());

  EXPECT_TRUE(client->getReadCallbacks().empty());
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    SetReadCallbackNullRemembersDelivery) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto id) {
    auto readData = client->read(id, 0);
    EXPECT_TRUE(readData->second);
  }));

  // delivers the eof
  auto data = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());

  client->setReadCallback(streamId, nullptr);

  AckBlocks sentPackets;
  auto writeData = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, writeData->clone(), true, false);
  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet2 = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet2->coalesce());

  ASSERT_EQ(
      client->getNonConstConn().streamManager->getStream(streamId), nullptr);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, StreamClosedIfReadCallbackNull) {
  // A RstStreamFrame will be written to sock when we receive a RstStreamFrame
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  AckBlocks sentPackets;
  auto writeData = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, writeData->clone(), true, false);
  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet2 = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet2->coalesce());

  // delivers the eof. Even though there is no read callback, we still need an
  // EOM or error to terminate the stream.
  auto data = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());

  ASSERT_EQ(
      client->getNonConstConn().streamManager->getStream(streamId), nullptr);
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveAckInvokesDeliveryCallback) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();
  client->registerDeliveryCallback(streamId, 0, &deliveryCallback);

  auto data = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, data->clone(), true, false);
  loopForWrites();

  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 0, _)).Times(1);
  deliverData(packet->coalesce());
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, InvokesDeliveryCallbackFinOnly) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto data = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, nullptr, true, false, &deliveryCallback);
  loopForWrites();

  verifyShortPackets(sentPackets);
  ASSERT_EQ(sentPackets.size(), 1);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, _, _)).Times(1);
  deliverData(packet->coalesce());
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportAfterStartTest,
    RegisterDeliveryCallbackForAlreadyDeliveredOffset) {
  AckBlocks sentPackets;

  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  auto data = IOBuf::copyBuffer("some data");
  client->writeChain(streamId, data->clone(), true, false);

  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());

  // Register a DeliveryCallback for an offset that's already delivered, will
  // callback immediately
  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 0, _)).Times(1);
  client->registerDeliveryCallback(streamId, 0, &deliveryCallback);
  eventbase_->loopOnce();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, DeliveryCallbackFromWriteChain) {
  AckBlocks sentPackets;
  auto streamId =
      client->createBidirectionalStream(false /* replaySafe */).value();

  // Write 10 bytes of data, and write EOF on an empty stream. So EOF offset is
  // 10
  auto data = test::buildRandomInputData(10);
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);

  loopForWrites();
  verifyShortPackets(sentPackets);

  // Write an AckFrame back to client:
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));

  // DeliveryCallback is called, and offset delivered is 10:
  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 10, _)).Times(1);
  deliverData(packet->coalesce());
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, NotifyPendingWrite) {
  NiceMock<MockWriteCallback> writeCallback;
  EXPECT_CALL(writeCallback, onConnectionWriteReady(_));
  client->notifyPendingWriteOnConnection(&writeCallback);
  loopForWrites();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, SwitchEvbWhileAsyncEventPending) {
  NiceMock<MockWriteCallback> writeCallback;
  EventBase evb2;
  EXPECT_CALL(writeCallback, onConnectionWriteReady(_)).Times(0);
  client->notifyPendingWriteOnConnection(&writeCallback);
  client->detachEventBase();
  client->attachEventBase(&evb2);
  loopForWrites();
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, StatelessResetClosesTransport) {
  // Make decrypt fail for the reset token
  auto aead = dynamic_cast<const MockAead*>(
      client->getNonConstConn().readCodec->getOneRttReadCipher());
  ASSERT_TRUE(aead);

  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return folly::none; }));

  auto token = *client->getConn().statelessResetToken;
  StatelessResetPacketBuilder builder(kDefaultUDPSendPacketLen, token);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(clientConnCallback, onConnectionError(_));
  deliverDataWithoutErrorCheck(packet->coalesce());
  EXPECT_TRUE(client->isClosed());
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, BadStatelessResetWontCloseTransport) {
  auto aead = dynamic_cast<const MockAead*>(
      client->getNonConstConn().readCodec->getOneRttReadCipher());
  ASSERT_TRUE(aead);
  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return folly::none; }));
  // Alter the expected token so it definitely won't match the one in conn
  auto token = *client->getConn().statelessResetToken;
  token[0] = ~token[0];
  StatelessResetPacketBuilder builder(kDefaultUDPSendPacketLen, token);
  auto packet = std::move(builder).buildPacket();
  // onConnectionError won't be invoked
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  deliverDataWithoutErrorCheck(packet->coalesce());
  EXPECT_FALSE(client->isClosed());
  EXPECT_FALSE(client->isDraining());
  client.reset();
  EXPECT_FALSE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportVersionAndRetryTest, RetryPacket) {
  std::vector<uint8_t> clientConnIdVec = {};
  ConnectionId clientConnId(clientConnIdVec);

  ConnectionId initialDstConnId(kInitialDstConnIdVecForRetryTest);

  // Create a stream and attempt to send some data to the server
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  client->getNonConstConn().readCodec->setClientConnectionId(clientConnId);
  client->getNonConstConn().initialDestinationConnectionId = initialDstConnId;
  client->getNonConstConn().originalDestinationConnectionId = initialDstConnId;

  StreamId streamId = *client->createBidirectionalStream();
  auto write = IOBuf::copyBuffer("ice cream");
  client->writeChain(streamId, write->clone(), true, false, nullptr);
  loopForWrites();

  std::unique_ptr<IOBuf> bytesWrittenToNetwork = nullptr;

  EXPECT_CALL(*sock, write(_, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            bytesWrittenToNetwork = buf->clone();
            return buf->computeChainDataLength();
          }));

  auto serverCid = recvServerRetry(serverAddr);
  ASSERT_TRUE(bytesWrittenToNetwork);

  // Check to see that the server receives an initial packet with the following
  // properties:
  // 1. The token in the initial packet matches the token sent in the retry
  // packet
  // 2. The destination connection id matches the connection id that the server
  // chose when it sent the retry packet
  AckStates ackStates;
  auto packetQueue = bufToQueue(bytesWrittenToNetwork->clone());
  auto codecResult =
      makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);

  auto& regularQuicPacket = *codecResult.regularPacket();
  auto& header = *regularQuicPacket.header.asLong();

  EXPECT_EQ(header.getHeaderType(), LongHeader::Types::Initial);
  EXPECT_TRUE(header.hasToken());
  EXPECT_EQ(header.getToken(), std::string("token"));
  EXPECT_EQ(header.getDestinationConnId(), serverCid);

  eventbase_->loopOnce();
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportVersionAndRetryTest,
    VersionNegotiationPacketNotSupported) {
  StreamId streamId = *client->createBidirectionalStream();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);
  loopForWrites();
  auto packet = VersionNegotiationPacketBuilder(
                    *client->getConn().initialDestinationConnectionId,
                    *originalConnId,
                    {MVFST2})
                    .buildPacket();
  EXPECT_CALL(
      readCb,
      readError(streamId, IsError(LocalErrorCode::CONNECTION_ABANDONED)));
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, write->length()));
  EXPECT_THROW(deliverData(packet.second->coalesce()), std::runtime_error);

  EXPECT_EQ(client->getConn().oneRttWriteCipher.get(), nullptr);
  EXPECT_CALL(clientConnCallback, onTransportReady()).Times(0);
  EXPECT_CALL(clientConnCallback, onReplaySafe()).Times(0);
  client->close(folly::none);
}

TEST_F(
    QuicClientTransportVersionAndRetryTest,
    VersionNegotiationPacketCurrentVersion) {
  StreamId streamId = *client->createBidirectionalStream();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);
  loopForWrites();

  auto packet = VersionNegotiationPacketBuilder(
                    *client->getConn().initialDestinationConnectionId,
                    *originalConnId,
                    {QuicVersion::MVFST})
                    .buildPacket();
  EXPECT_THROW(deliverData(packet.second->coalesce()), std::runtime_error);
  client->close(folly::none);
}

TEST_F(QuicClientTransportVersionAndRetryTest, UnencryptedStreamData) {
  StreamId streamId = *client->createBidirectionalStream();
  auto expected = IOBuf::copyBuffer("hello");
  PacketNum nextPacketNum = appDataPacketNum++;
  auto packet = packetToBufCleartext(
      createStreamPacket(
          *serverChosenConnId /* src */,
          *originalConnId /* dest */,
          nextPacketNum,
          streamId,
          *expected,
          getInitialCipher().getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_THROW(deliverData(packet->coalesce()), std::runtime_error);
}

TEST_F(QuicClientTransportVersionAndRetryTest, UnencryptedAckData) {
  AckBlocks acks = {{1, 2}};
  auto expected = IOBuf::copyBuffer("hello");
  PacketNum nextPacketNum = initialPacketNum++;
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(),
      *client->getConn().clientConnectionId,
      nextPacketNum,
      version);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  DCHECK(builder.canBuildPacket());
  AckFrameMetaData ackData(acks, 0us, 0);
  writeAckFrame(ackData, builder);
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_NO_THROW(deliverData(packet->coalesce()));
}

TEST_F(QuicClientTransportVersionAndRetryTest, UnencryptedPing) {
  PacketNum nextPacketNum = initialPacketNum++;
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(),
      *client->getConn().clientConnectionId,
      nextPacketNum,
      version);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  DCHECK(builder.canBuildPacket());
  writeFrame(PingFrame(), builder);
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      getInitialCipher(),
      getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_NO_THROW(deliverData(packet->coalesce()));
}

Buf getHandshakePacketWithFrame(
    QuicWriteFrame frame,
    ConnectionId srcConnId,
    ConnectionId destConnId,
    const Aead& serverWriteCipher,
    const PacketNumberCipher& headerCipher) {
  PacketNum packetNum = folly::Random::rand32();
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      destConnId,
      packetNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      std::move(header),
      packetNum / 2 /* largestAcked */);
  builder.encodePacketHeader();
  builder.accountForCipherOverhead(serverWriteCipher.getCipherOverhead());
  writeFrame(std::move(frame), builder);
  return packetToBufCleartext(
      std::move(builder).buildPacket(),
      serverWriteCipher,
      headerCipher,
      packetNum);
}

TEST_F(QuicClientTransportVersionAndRetryTest, FrameNotAllowed) {
  StreamId streamId = *client->createBidirectionalStream();
  auto clientConnectionId = *client->getConn().clientConnectionId;
  auto serverConnId = *serverChosenConnId;
  serverConnId.data()[0] = ~serverConnId.data()[0];

  EXPECT_THROW(
      deliverData(getHandshakePacketWithFrame(
                      MaxStreamDataFrame(streamId, 100),
                      serverConnId /* src */,
                      clientConnectionId /* dest */,
                      getInitialCipher(),
                      getInitialHeaderCipher())
                      ->coalesce()),
      std::runtime_error);
  EXPECT_TRUE(client->error());
  EXPECT_EQ(client->getConn().clientConnectionId, *originalConnId);
}

TEST_F(QuicClientTransportAfterStartTest, SendReset) {
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  client->registerDeliveryCallback(streamId, 100, &deliveryCallback);
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, 100));
  EXPECT_CALL(readCb, readError(streamId, _));
  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  verifyShortPackets(sentPackets);

  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  // ReadCallbacks are not affected by reseting send state
  EXPECT_EQ(1, readCbs.count(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(conn.streamManager->writableContains(streamId));
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream is not yet closed because ingress state machine is open
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

RegularQuicWritePacket* findPacketWithStream(
    QuicConnectionStateBase& conn,
    StreamId streamId) {
  auto op = findOutstandingPacket(conn, [=](OutstandingPacket& packet) {
    for (auto& frame : packet.packet.frames) {
      bool tryPacket = false;
      WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
      if (streamFrame) {
        tryPacket = streamFrame->streamId == streamId;
      }
      if (tryPacket) {
        return true;
      }
    }
    return false;
  });
  if (op) {
    return &(op->packet);
  }
  return nullptr;
}

TEST_F(QuicClientTransportAfterStartTest, ResetClearsPendingLoss) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  SCOPE_EXIT {
    client->close(folly::none);
  };
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  RegularQuicWritePacket* forceLossPacket =
      CHECK_NOTNULL(findPacketWithStream(client->getNonConstConn(), streamId));
  markPacketLoss(client->getNonConstConn(), *forceLossPacket, false);
  auto& pendingLossStreams = client->getConn().streamManager->lossStreams();
  ASSERT_TRUE(pendingLossStreams.count(streamId) > 0);

  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(pendingLossStreams.count(streamId) == 0);
}

TEST_F(QuicClientTransportAfterStartTest, LossAfterResetStream) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  SCOPE_EXIT {
    client->close(folly::none);
  };
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  ASSERT_FALSE(client->getConn().outstandings.packets.empty());

  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);

  RegularQuicWritePacket* forceLossPacket =
      CHECK_NOTNULL(findPacketWithStream(client->getNonConstConn(), streamId));
  markPacketLoss(client->getNonConstConn(), *forceLossPacket, false);
  auto stream = CHECK_NOTNULL(
      client->getNonConstConn().streamManager->getStream(streamId));
  ASSERT_TRUE(stream->lossBuffer.empty());
  auto& pendingLossStreams = client->getConn().streamManager->lossStreams();
  ASSERT_TRUE(pendingLossStreams.count(streamId) == 0);
}

TEST_F(QuicClientTransportAfterStartTest, SendResetAfterEom) {
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  client->registerDeliveryCallback(streamId, 100, &deliveryCallback);
  EXPECT_CALL(deliveryCallback, onCanceled(streamId, 100));
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);

  client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  verifyShortPackets(sentPackets);
  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  // ReadCallback are not affected by reseting send state.
  EXPECT_EQ(1, readCbs.count(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(conn.streamManager->writableContains(streamId));

  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream still exists since ingress state machine is still open
  EXPECT_TRUE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, HalfClosedLocalToClosed) {
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  auto data = test::buildRandomInputData(10);
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);
  loopForWrites();

  verifyShortPackets(sentPackets);

  const auto& conn = client->getConn();
  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 10, _)).Times(1);
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  EXPECT_FALSE(conn.streamManager->deliverableContains(streamId));

  bool dataDelivered = false;
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 100);
    auto copy = readData->first->clone();
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  const auto& readCbs = client->getReadCallbacks();
  EXPECT_EQ(0, readCbs.count(streamId));
  EXPECT_EQ(0, conn.streamManager->readableStreams().count(streamId));
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, SendResetSyncOnAck) {
  AckBlocks sentPackets;
  StreamId streamId = client->createBidirectionalStream().value();
  StreamId streamId2 = client->createBidirectionalStream().value();

  NiceMock<MockDeliveryCallback> deliveryCallback2;
  auto data = IOBuf::copyBuffer("hello");
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);
  client->writeChain(streamId2, data->clone(), true, false, &deliveryCallback2);

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, _, _))
      .WillOnce(Invoke([&](auto, auto, auto) {
        client->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
        client->resetStream(streamId2, GenericApplicationErrorCode::UNKNOWN);
      }));
  auto packet1 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto packet2 = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(packet1->coalesce());
  deliverData(packet2->coalesce());
  loopForWrites();
  verifyShortPackets(sentPackets);

  const auto& readCbs = client->getReadCallbacks();
  const auto& conn = client->getConn();
  EXPECT_EQ(0, readCbs.count(streamId));
  // readable list can still be populated after a reset.
  EXPECT_FALSE(conn.streamManager->writableContains(streamId));
  auto packet = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(packet->coalesce());
  // Stream should be closed after it received the ack for rst
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, HalfClosedRemoteToClosed) {
  StreamId streamId = client->createBidirectionalStream().value();
  client->setReadCallback(streamId, &readCb);
  auto data = test::buildRandomInputData(10);
  auto packet = packetToBuf(createStreamPacket(
      *serverChosenConnId /* src */,
      *originalConnId /* dest */,
      appDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  bool dataDelivered = false;
  EXPECT_CALL(readCb, readAvailable(streamId)).WillOnce(Invoke([&](auto) {
    auto readData = client->read(streamId, 100);
    auto copy = readData->first->clone();
    dataDelivered = true;
    eventbase_->terminateLoopSoon();
  }));
  const auto& conn = client->getConn();
  deliverData(packet->coalesce());
  if (!dataDelivered) {
    eventbase_->loopForever();
  }
  EXPECT_TRUE(dataDelivered);
  const auto& readCbs = client->getReadCallbacks();
  EXPECT_EQ(readCbs.count(streamId), 1);
  EXPECT_EQ(conn.streamManager->readableStreams().count(streamId), 0);

  AckBlocks sentPackets;
  client->writeChain(streamId, data->clone(), true, false, &deliveryCallback);
  loopForWrites();

  verifyShortPackets(sentPackets);

  EXPECT_CALL(deliveryCallback, onDeliveryAck(streamId, 10, _)).Times(1);
  auto ackPacket = packetToBuf(createAckPacket(
      client->getNonConstConn(),
      ++appDataPacketNum,
      sentPackets,
      PacketNumberSpace::AppData));
  deliverData(ackPacket->coalesce());
  EXPECT_FALSE(conn.streamManager->hasDeliverable());
  EXPECT_FALSE(conn.streamManager->streamExists(streamId));
  EXPECT_EQ(readCbs.count(streamId), 0);
  client->close(folly::none);
  EXPECT_TRUE(client->isClosed());
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveConnectionClose) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  builder.encodePacketHeader();
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      "Stand clear of the closing doors, please");
  writeFrame(std::move(connClose), builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_CALL(clientConnCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->first);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeHandshakeCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveApplicationClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  builder.encodePacketHeader();
  ConnectionCloseFrame appClose(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      "Stand clear of the closing doors, please");
  writeFrame(std::move(appClose), builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_FALSE(client->isClosed());
  socketWrites.clear();

  EXPECT_CALL(
      clientConnCallback,
      onConnectionError(IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->first);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeHandshakeCodec(),
      QuicFrame::Type::ConnectionCloseFrame));

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(
      event->update,
      getPeerClose(
          "Client closed by peer reason=Stand clear of the closing doors, please"));
}

TEST_F(QuicClientTransportAfterStartTest, ReceiveApplicationCloseNoError) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen, std::move(header), 0);
  builder.encodePacketHeader();
  ConnectionCloseFrame appClose(
      QuicErrorCode(GenericApplicationErrorCode::NO_ERROR), "No Error");
  writeFrame(std::move(appClose), builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  EXPECT_FALSE(client->isClosed());
  socketWrites.clear();

  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packet->coalesce());
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      client->getConn().localConnectionError->first);
  EXPECT_TRUE(client->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      socketWrites,
      *makeHandshakeCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicClientTransportAfterStartTest, DestroyWithoutClosing) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd());

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);
  loopForWrites();

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));
}

TEST_F(QuicClientTransportAfterStartTest, DestroyWhileDraining) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false, &deliveryCallback);

  loopForWrites();
  EXPECT_CALL(clientConnCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(clientConnCallback, onConnectionEnd()).Times(0);
  // Go into draining with one active stream.

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));
  client->close(folly::none);
}

TEST_F(QuicClientTransportAfterStartTest, CloseNowWhileDraining) {
  // Drain first with no active streams
  auto err = std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str());
  client->close(err);
  EXPECT_TRUE(client->isDraining());
  client->closeNow(err);
  EXPECT_FALSE(client->isDraining());
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, ExpiredDrainTimeout) {
  auto err = std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str());
  client->close(err);
  EXPECT_TRUE(client->isDraining());
  EXPECT_FALSE(destructionCallback->isDestroyed());
  client->drainTimeout().timeoutExpired();
  client.reset();
  EXPECT_TRUE(destructionCallback->isDestroyed());
}

TEST_F(QuicClientTransportAfterStartTest, WriteThrowsExceptionWhileDraining) {
  // Drain first with no active streams
  auto err = std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str());
  EXPECT_CALL(*sock, write(_, _)).WillRepeatedly(SetErrnoAndReturn(EBADF, -1));
  client->close(err);
  EXPECT_FALSE(client->idleTimeout().isScheduled());
}

TEST_F(QuicClientTransportAfterStartTest, DestroyEvbWhileLossTimeoutActive) {
  StreamId streamId = client->createBidirectionalStream().value();

  client->setReadCallback(streamId, &readCb);

  auto write = IOBuf::copyBuffer("no");
  client->writeChain(streamId, write->clone(), true, false);
  loopForWrites();
  EXPECT_TRUE(client->lossTimeout().isScheduled());
  eventbase_.reset();
}

TEST_F(QuicClientTransportAfterStartTest, SetCongestionControl) {
  // Default: Cubic
  auto cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Change to Reno
  client->setCongestionControl(CongestionControlType::NewReno);
  cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::NewReno, cc->type());

  // Change back to Cubic:
  client->setCongestionControl(CongestionControlType::Cubic);
  cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());
}

TEST_F(QuicClientTransportAfterStartTest, SetCongestionControlBbr) {
  // Default: Cubic
  auto cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Change to BBR, which requires enable pacing first
  client->setPacingTimer(TimerHighRes::newTimer(eventbase_.get(), 1ms));
  client->getNonConstConn().transportSettings.pacingEnabled = true;
  client->setCongestionControl(CongestionControlType::BBR);
  cc = client->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::BBR, cc->type());
}

TEST_F(QuicClientTransportAfterStartTest, PingIsTreatedAsRetransmittable) {
  PingFrame pingFrame;
  ShortHeader header(
      ProtectionType::KeyPhaseZero, *originalConnId, appDataPacketNum++);
  RegularQuicPacketBuilder builder(
      client->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  writeFrame(pingFrame, builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(packet->coalesce());
  EXPECT_TRUE(client->getConn().pendingEvents.scheduleAckTimeout);
}

TEST_F(QuicClientTransportAfterStartTest, OneCloseFramePerRtt) {
  auto streamId = client->createBidirectionalStream().value();
  auto& conn = client->getNonConstConn();
  conn.lossState.srtt = 10s;
  EXPECT_CALL(*sock, write(_, _)).WillRepeatedly(Return(100));
  loopForWrites();
  Mock::VerifyAndClearExpectations(sock);

  // Close the client transport. There could be multiple writes given how many
  // ciphers we have.
  EXPECT_CALL(*sock, write(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(10));
  client->close(std::make_pair<QuicErrorCode, std::string>(
      QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
      toString(LocalErrorCode::INTERNAL_ERROR).str()));
  EXPECT_TRUE(conn.lastCloseSentTime.hasValue());
  Mock::VerifyAndClearExpectations(sock);

  // Then received some server packet, which won't trigger another close
  EXPECT_CALL(*sock, write(_, _)).Times(0);
  auto firstData = folly::IOBuf::copyBuffer(
      "I got a room full of your posters and your pictures, man");
  deliverDataWithoutErrorCheck(packetToBuf(createStreamPacket(
                                               *serverChosenConnId,
                                               *originalConnId,
                                               appDataPacketNum++,
                                               streamId,
                                               *firstData,
                                               0 /* cipherOverhead */,
                                               0 /* largestAcked */))
                                   ->coalesce());
  Mock::VerifyAndClearExpectations(sock);

  // force the clock:
  conn.lastCloseSentTime = Clock::now() - 10s;
  conn.lossState.srtt = 1us;
  // Receive another server packet
  EXPECT_CALL(*sock, write(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(10));
  auto secondData = folly::IOBuf::copyBuffer(
      "Dear Slim, I wrote to you but you still ain't callin'");
  deliverDataWithoutErrorCheck(packetToBuf(createStreamPacket(
                                               *serverChosenConnId,
                                               *originalConnId,
                                               appDataPacketNum++,
                                               streamId,
                                               *secondData,
                                               0 /* cipherOverhead */,
                                               0 /* largestAcked */))
                                   ->coalesce());
}

TEST_F(QuicClientVersionParamInvalidTest, InvalidVersion) {
  EXPECT_THROW(performFakeHandshake(), std::runtime_error);
}

class QuicClientTransportPskCacheTest
    : public QuicClientTransportAfterStartTestBase {
 public:
  void SetUpChild() override {
    QuicClientTransportAfterStartTestBase::SetUpChild();
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    mockPskCache_ = std::make_shared<NiceMock<MockQuicPskCache>>();
    return mockPskCache_;
  }

 protected:
  std::shared_ptr<MockQuicPskCache> mockPskCache_;
};

TEST_F(QuicClientTransportPskCacheTest, TestOnNewCachedPsk) {
  std::string appParams = "APP params";
  client->setEarlyDataAppParamsFunctions(
      [](const folly::Optional<std::string>&, const Buf&) { return true; },
      [=]() -> Buf { return folly::IOBuf::copyBuffer(appParams); });
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        EXPECT_EQ(psk.appParams, appParams);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

TEST_F(QuicClientTransportPskCacheTest, TestTwoOnNewCachedPsk) {
  std::string appParams1 = "APP params1";
  client->setEarlyDataAppParamsFunctions(
      [](const folly::Optional<std::string>&, const Buf&) { return true; },
      [=]() -> Buf { return folly::IOBuf::copyBuffer(appParams1); });
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote, kDefaultStreamWindowSize);
        EXPECT_EQ(params.initialMaxStreamDataUni, kDefaultStreamWindowSize);
        EXPECT_EQ(psk.appParams, appParams1);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();

  client->getNonConstConn().flowControlState.peerAdvertisedMaxOffset = 1234;
  client->getNonConstConn()
      .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal = 123;
  client->getNonConstConn()
      .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 123;
  client->getNonConstConn()
      .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni = 123;

  std::string appParams2 = "APP params2";
  client->setEarlyDataAppParamsFunctions(
      [](const folly::Optional<std::string>&, const Buf&) { return true; },
      [=]() -> Buf { return folly::IOBuf::copyBuffer(appParams2); });
  EXPECT_CALL(*mockPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote, kDefaultStreamWindowSize);
        EXPECT_EQ(params.initialMaxStreamDataUni, kDefaultStreamWindowSize);
        EXPECT_EQ(psk.appParams, appParams2);
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

class QuicZeroRttClientTest : public QuicClientTransportAfterStartTestBase {
 public:
  ~QuicZeroRttClientTest() override = default;

  void setFakeHandshakeCiphers() override {
    auto readAead = test::createNoOpAead();
    auto writeAead = test::createNoOpAead();
    auto zeroAead = test::createNoOpAead();
    auto handshakeReadAead = test::createNoOpAead();
    auto handshakeWriteAead = test::createNoOpAead();
    mockClientHandshake->setOneRttReadCipher(std::move(readAead));
    mockClientHandshake->setOneRttWriteCipher(std::move(writeAead));
    mockClientHandshake->setZeroRttWriteCipher(std::move(zeroAead));
    mockClientHandshake->setHandshakeReadCipher(std::move(handshakeReadAead));
    mockClientHandshake->setHandshakeWriteCipher(std::move(handshakeWriteAead));

    mockClientHandshake->setHandshakeReadHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setHandshakeWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttWriteHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setOneRttReadHeaderCipher(
        test::createNoOpHeaderCipher());
    mockClientHandshake->setZeroRttWriteHeaderCipher(
        test::createNoOpHeaderCipher());
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    if (!mockQuicPskCache_) {
      mockQuicPskCache_ = std::make_shared<MockQuicPskCache>();
    }
    return mockQuicPskCache_;
  }

  void start() override {
    TransportSettings clientSettings;
    // Ignore path mtu to test negotiation.
    clientSettings.canIgnorePathMTU = true;
    clientSettings.attemptEarlyData = true;
    client->setTransportSettings(clientSettings);
  }

  void startClient() {
    EXPECT_CALL(clientConnCallback, onTransportReady());
    client->start(&clientConnCallback);
    setConnectionIds();
    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
  }

  bool zeroRttPacketsOutstanding() {
    for (auto& packet : client->getNonConstConn().outstandings.packets) {
      bool isZeroRtt =
          packet.packet.header.getProtectionType() == ProtectionType::ZeroRtt;
      if (isZeroRtt) {
        return true;
      }
    }
    return false;
  }

 protected:
  std::shared_ptr<MockQuicPskCache> mockQuicPskCache_;
};

TEST_F(QuicZeroRttClientTest, TestReplaySafeCallback) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) {
        performedValidation = true;
        return true;
      },
      []() -> Buf { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  mockClientHandshake->setZeroRttRejected(false);
  recvServerHello();

  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);

  // All the data is still there.
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  // Transport parameters did not change since zero rtt was accepted.
  // Except for max packet size.
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultMaxUDPPayload);

  EXPECT_CALL(*mockQuicPskCache_, putPsk(hostname_, _))
      .WillOnce(Invoke([=](const std::string&, QuicCachedPsk psk) {
        auto& params = psk.transportParams;
        EXPECT_EQ(params.initialMaxData, kDefaultConnectionWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiLocal, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamDataBidiRemote, kDefaultStreamWindowSize);
        EXPECT_EQ(params.initialMaxStreamDataUni, kDefaultStreamWindowSize);
        EXPECT_EQ(
            params.initialMaxStreamsBidi, std::numeric_limits<uint32_t>::max());
        EXPECT_EQ(
            params.initialMaxStreamsUni, std::numeric_limits<uint32_t>::max());
      }));
  mockClientHandshake->triggerOnNewCachedPsk();
}

TEST_F(QuicZeroRttClientTest, TestZeroRttRejection) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) {
        performedValidation = true;
        return true;
      },
      []() -> Buf { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  EXPECT_CALL(clientConnCallback, onReplaySafe());
  mockClientHandshake->setZeroRttRejected(true);
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  recvServerHello();
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);
  // Zero rtt data is declared lost.
  EXPECT_FALSE(zeroRttPacketsOutstanding());
  EXPECT_EQ(client->getConn().zeroRttWriteCipher, nullptr);
}

TEST_F(QuicZeroRttClientTest, TestZeroRttRejectionWithSmallerFlowControl) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  bool performedValidation = false;
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) {
        performedValidation = true;
        return true;
      },
      []() -> Buf { return nullptr; });
  startClient();
  EXPECT_TRUE(performedValidation);

  mockClientHandshake->maxInitialStreamData = 10;
  socketWrites.clear();
  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  mockClientHandshake->setZeroRttRejected(true);
  EXPECT_CALL(*mockQuicPskCache_, removePsk(hostname_));
  EXPECT_THROW(recvServerHello(), std::runtime_error);
}

class QuicZeroRttHappyEyeballsClientTransportTest
    : public QuicZeroRttClientTest {
 public:
  void SetUpChild() override {
    client->setHostname(hostname_);

    auto secondSocket =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
            eventbase_.get());
    secondSock = secondSocket.get();

    client->setHappyEyeballsEnabled(true);
    client->addNewPeerAddress(firstAddress);
    client->addNewPeerAddress(secondAddress);
    client->addNewSocket(std::move(secondSocket));

    EXPECT_EQ(client->getConn().happyEyeballsState.v6PeerAddress, firstAddress);
    EXPECT_EQ(
        client->getConn().happyEyeballsState.v4PeerAddress, secondAddress);

    setupCryptoLayer();
  }

  std::shared_ptr<QuicPskCache> getPskCache() override {
    if (!mockQuicPskCache_) {
      mockQuicPskCache_ = std::make_shared<MockQuicPskCache>();
    }
    return mockQuicPskCache_;
  }

 protected:
  folly::test::MockAsyncUDPSocket* secondSock;
  SocketAddress firstAddress{"::1", 443};
  SocketAddress secondAddress{"127.0.0.1", 443};
};

TEST_F(
    QuicZeroRttHappyEyeballsClientTransportTest,
    ZeroRttDataIsRetransmittedOverSecondSocket) {
  EXPECT_CALL(*mockQuicPskCache_, getPsk(hostname_))
      .WillOnce(InvokeWithoutArgs([]() {
        QuicCachedPsk quicCachedPsk;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxStreamDataUni =
            kDefaultStreamWindowSize;
        quicCachedPsk.transportParams.initialMaxData =
            kDefaultConnectionWindowSize;
        quicCachedPsk.transportParams.idleTimeout = kDefaultIdleTimeout.count();
        quicCachedPsk.transportParams.maxRecvPacketSize =
            kDefaultUDPReadBufferSize;
        quicCachedPsk.transportParams.initialMaxStreamsBidi =
            std::numeric_limits<uint32_t>::max();
        quicCachedPsk.transportParams.initialMaxStreamsUni =
            std::numeric_limits<uint32_t>::max();
        return quicCachedPsk;
      }));
  client->setEarlyDataAppParamsFunctions(
      [&](const folly::Optional<std::string>&, const Buf&) { return true; },
      []() -> Buf { return nullptr; });

  EXPECT_CALL(*sock, write(firstAddress, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            socketWrites.push_back(buf->clone());
            return buf->computeChainDataLength();
          }));
  EXPECT_CALL(*secondSock, write(_, _)).Times(0);
  startClient();
  socketWrites.clear();
  auto& conn = client->getConn();
  EXPECT_EQ(conn.peerAddress, firstAddress);
  EXPECT_EQ(conn.happyEyeballsState.secondPeerAddress, secondAddress);
  EXPECT_TRUE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
  // Cancel the delay timer because we want to manually fire it
  client->happyEyeballsConnAttemptDelayTimeout().cancelTimeout();

  auto streamId = client->createBidirectionalStream().value();
  client->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  EXPECT_TRUE(zeroRttPacketsOutstanding());
  assertWritten(false, LongHeader::Types::ZeroRtt);
  socketWrites.clear();

  // Manually expire conn attempt timeout
  EXPECT_FALSE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  client->happyEyeballsConnAttemptDelayTimeout().timeoutExpired();
  EXPECT_TRUE(conn.happyEyeballsState.shouldWriteToSecondSocket);
  EXPECT_FALSE(client->happyEyeballsConnAttemptDelayTimeout().isScheduled());
  // Declared lost
  EXPECT_FALSE(zeroRttPacketsOutstanding());

  // Manually expire loss timeout to trigger write to both first and second
  // socket
  EXPECT_CALL(*sock, write(firstAddress, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            socketWrites.push_back(
                folly::IOBuf::copyBuffer(buf->data(), buf->length(), 0, 0));
            return buf->length();
          }));
  EXPECT_CALL(*secondSock, write(secondAddress, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const std::unique_ptr<folly::IOBuf>& buf) {
            socketWrites.push_back(buf->clone());
            return buf->computeChainDataLength();
          }));
  client->lossTimeout().cancelTimeout();
  client->lossTimeout().timeoutExpired();
  EXPECT_EQ(socketWrites.size(), 4);
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(1), LongHeader::Types::Initial));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(2), LongHeader::Types::ZeroRtt));
  EXPECT_TRUE(
      verifyLongHeader(*socketWrites.at(3), LongHeader::Types::ZeroRtt));
}

class QuicProcessDataTest : public QuicClientTransportAfterStartTestBase,
                            public testing::WithParamInterface<uint8_t> {
 public:
  ~QuicProcessDataTest() override = default;

  void start() override {
    // force the server to declare that the version negotiated was invalid.;
    mockClientHandshake->negotiatedVersion = QuicVersion::QUIC_DRAFT;
    client->setSupportedVersions({QuicVersion::QUIC_DRAFT});
    client->start(&clientConnCallback);
    setConnectionIds();
  }
};

INSTANTIATE_TEST_CASE_P(
    QuicClientZeroLenConnIds,
    QuicProcessDataTest,
    ::Values(0, 8));

TEST_F(QuicProcessDataTest, ProcessDataWithGarbageAtEnd) {
  expectQuicStatsPacketDrop(
      QuicTransportStatsCallback::PacketDropReason::PARSE_ERROR);
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto params = mockClientHandshake->getServerTransportParams();
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::initial_source_connection_id, *serverChosenConnId));
  params->parameters.push_back(encodeConnIdParameter(
      TransportParameterId::original_destination_connection_id,
      *client->getConn().initialDestinationConnectionId));
  mockClientHandshake->setServerTransportParams(std::move(*params));
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_DRAFT,
      ProtectionType::Initial,
      *serverHello,
      aead,
      0 /* largestAcked */);
  auto packetData = packetToBufCleartext(
      packet, aead, getInitialHeaderCipher(), nextPacketNum);
  packetData->prependChain(IOBuf::copyBuffer("garbage in"));
  deliverData(serverAddr, packetData->coalesce());
  verifyTransportParameters(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      mockClientHandshake->maxRecvPacketSize);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 10);
  EXPECT_EQ(event->dropReason, kParse);
}

TEST_P(QuicProcessDataTest, ProcessDataHeaderOnly) {
  uint8_t connIdSize = GetParam();
  client->getNonConstConn().clientConnectionId =
      ConnectionId(std::vector<uint8_t>(connIdSize, 1));
  setConnectionIds();

  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  client->getNonConstConn().qLogger = qLogger;
  auto serverHello = IOBuf::copyBuffer("Fake SHLO");
  PacketNum nextPacketNum = initialPacketNum++;
  auto& aead = getInitialCipher();
  auto largestReceivedPacketNum =
      getAckState(client->getConn(), PacketNumberSpace::Handshake)
          .largestReceivedPacketNum;
  auto packet = createCryptoPacket(
      *serverChosenConnId,
      *originalConnId,
      nextPacketNum,
      QuicVersion::QUIC_DRAFT,
      ProtectionType::Initial,
      *serverHello,
      aead,
      0 /* largestAcked */);

  deliverData(serverAddr, packet.header->coalesce());
  EXPECT_EQ(
      getAckState(client->getConn(), PacketNumberSpace::Handshake)
          .largestReceivedPacketNum,
      largestReceivedPacketNum);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::DatagramReceived, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogDatagramReceivedEvent*>(tmp.get());
  EXPECT_EQ(event->dataLen, 18 + connIdSize);
}

TEST(AsyncUDPSocketTest, CloseMultipleTimes) {
  class EmptyReadCallback : public AsyncUDPSocket::ReadCallback {
   public:
    void getReadBuffer(void**, size_t*) noexcept override {}
    void onDataAvailable(
        const folly::SocketAddress&,
        size_t,
        bool,
        OnDataAvailableParams) noexcept override {}
    void onReadError(const AsyncSocketException&) noexcept override {}
    void onReadClosed() noexcept override {}
  };

  class EmptyErrMessageCallback : public AsyncUDPSocket::ErrMessageCallback {
   public:
    void errMessage(const cmsghdr&) noexcept override {}
    void errMessageError(const AsyncSocketException&) noexcept override {}
  };

  EventBase evb;
  AsyncUDPSocket socket(&evb);
  TransportSettings transportSettings;
  EmptyErrMessageCallback errMessageCallback;
  EmptyReadCallback readCallback;
  happyEyeballsSetUpSocket(
      socket,
      folly::none,
      folly::SocketAddress("127.0.0.1", 12345),
      transportSettings,
      &errMessageCallback,
      &readCallback,
      folly::emptySocketOptionMap);

  socket.pauseRead();
  socket.close();
  socket.pauseRead();
  socket.close();
}
} // namespace test
} // namespace quic
