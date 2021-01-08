/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/QuicServerTransport.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/fizz/server/handshake/FizzServerHandshake.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/FileQLogger.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/server/test/Mocks.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/test/MockQuicStats.h>

#include <folly/io/async/test/MockAsyncUDPSocket.h>

using namespace testing;
using namespace folly;

namespace quic {
namespace test {

namespace {
using ByteEvent = QuicTransportBase::ByteEvent;
using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;
} // namespace

class FakeServerHandshake : public FizzServerHandshake {
 public:
  explicit FakeServerHandshake(
      QuicServerConnectionState& conn,
      std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext,
      bool chloSync = false,
      bool cfinSync = false,
      folly::Optional<uint64_t> clientActiveConnectionIdLimit = folly::none)
      : FizzServerHandshake(&conn, std::move(fizzContext)),
        conn_(conn),
        chloSync_(chloSync),
        cfinSync_(cfinSync),
        clientActiveConnectionIdLimit_(clientActiveConnectionIdLimit) {}

  void accept(std::shared_ptr<ServerTransportParametersExtension>) override {}

  MOCK_METHOD1(writeNewSessionTicket, void(const AppToken&));

  void doHandshake(std::unique_ptr<IOBuf> data, EncryptionLevel) override {
    IOBufEqualTo eq;
    auto chlo = folly::IOBuf::copyBuffer("CHLO");
    auto clientFinished = IOBuf::copyBuffer("FINISHED");
    if (eq(data, chlo)) {
      if (chloSync_) {
        // Do NOT invoke onCryptoEventAvailable callback
        // Fall through and let the ServerStateMachine to process the event
        writeDataToQuicStream(
            *getCryptoStream(*conn_.cryptoState, EncryptionLevel::Initial),
            IOBuf::copyBuffer("SHLO"));
        if (allowZeroRttKeys_) {
          validateAndUpdateSourceToken(conn_, sourceAddrs_);
          phase_ = Phase::KeysDerived;
          setEarlyKeys();
        }
        setHandshakeKeys();
      } else {
        // Asynchronously schedule the callback
        executor_->add([&] {
          writeDataToQuicStream(
              *getCryptoStream(*conn_.cryptoState, EncryptionLevel::Initial),
              IOBuf::copyBuffer("SHLO"));
          if (allowZeroRttKeys_) {
            validateAndUpdateSourceToken(conn_, sourceAddrs_);
            phase_ = Phase::KeysDerived;
            setEarlyKeys();
          }
          setHandshakeKeys();
          if (callback_) {
            callback_->onCryptoEventAvailable();
          }
        });
      }
    } else if (eq(data, clientFinished)) {
      if (cfinSync_) {
        // Do NOT invoke onCryptoEventAvailable callback
        // Fall through and let the ServerStateMachine to process the event
        setOneRttKeys();
        phase_ = Phase::Established;
        handshakeDone_ = true;
      } else {
        // Asynchronously schedule the callback
        executor_->add([&] {
          setOneRttKeys();
          phase_ = Phase::Established;
          handshakeDone_ = true;
          if (callback_) {
            callback_->onCryptoEventAvailable();
          }
        });
      }
    }
  }

  folly::Optional<ClientTransportParameters> getClientTransportParams() override {
    std::vector<TransportParameter> transportParams;
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        kDefaultStreamWindowSize));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        kDefaultStreamWindowSize));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        kDefaultStreamWindowSize));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi,
        kDefaultMaxStreamsBidirectional));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni,
        kDefaultMaxStreamsUnidirectional));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::initial_max_data, kDefaultConnectionWindowSize));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::idle_timeout, kDefaultIdleTimeout.count()));
    transportParams.push_back(encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize));
    if (clientActiveConnectionIdLimit_) {
      transportParams.push_back(encodeIntegerParameter(
          TransportParameterId::active_connection_id_limit,
          *clientActiveConnectionIdLimit_));
    }
    transportParams.push_back(encodeConnIdParameter(
        TransportParameterId::initial_source_connection_id,
        getTestConnectionId()));

    return ClientTransportParameters{std::move(transportParams)};
  }

  void setEarlyKeys() {
    oneRttWriteCipher_ = createNoOpAead();
    oneRttWriteHeaderCipher_ = createNoOpHeaderCipher();
    zeroRttReadCipher_ = createNoOpAead();
    zeroRttReadHeaderCipher_ = createNoOpHeaderCipher();
  }

  void setOneRttKeys() {
    // Mimic ServerHandshake behavior.
    // oneRttWriteCipher would already be set during ReportEarlyHandshakeSuccess
    if (!allowZeroRttKeys_) {
      oneRttWriteCipher_ = createNoOpAead();
      oneRttWriteHeaderCipher_ = createNoOpHeaderCipher();
    }
    oneRttReadCipher_ = createNoOpAead();
    oneRttReadHeaderCipher_ = createNoOpHeaderCipher();
  }

  void setHandshakeKeys() {
    conn_.handshakeWriteCipher = createNoOpAead();
    conn_.handshakeWriteHeaderCipher = createNoOpHeaderCipher();
    handshakeReadCipher_ = createNoOpAead();
    handshakeReadHeaderCipher_ = createNoOpHeaderCipher();
  }

  void setHandshakeDone(bool done) {
    handshakeDone_ = done;
  }

  void allowZeroRttKeys() {
    allowZeroRttKeys_ = true;
  }

  void setSourceTokens(std::vector<folly::IPAddress> srcAddrs) {
    sourceAddrs_ = srcAddrs;
  }

  QuicServerConnectionState& conn_;
  bool chloSync_{false};
  bool cfinSync_{false};
  uint64_t maxRecvPacketSize{kDefaultMaxUDPPayload};
  bool allowZeroRttKeys_{false};
  std::vector<folly::IPAddress> sourceAddrs_;
  folly::Optional<uint64_t> clientActiveConnectionIdLimit_;
};

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

struct MigrationParam {
  folly::Optional<uint64_t> clientSentActiveConnIdTransportParam;
};

class TestingQuicServerTransport : public QuicServerTransport {
 public:
  TestingQuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionCallback& cb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicServerTransport(evb, std::move(sock), cb, ctx) {}

  const QuicServerConnectionState& getConn() const {
    return *dynamic_cast<QuicServerConnectionState*>(conn_.get());
  }

  QuicServerConnectionState& getNonConstConn() {
    return *dynamic_cast<QuicServerConnectionState*>(conn_.get());
  }

  AsyncUDPSocket& getSocket() {
    return *socket_;
  }

  auto& idleTimeout() {
    return idleTimeout_;
  }

  auto& drainTimeout() {
    return drainTimeout_;
  }

  auto& ackTimeout() {
    return ackTimeout_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  auto& pathValidationTimeout() {
    return pathValidationTimeout_;
  }

  bool isClosed() {
    return closeState_ == CloseState::CLOSED;
  }

  bool isDraining() {
    return drainTimeout_.isScheduled();
  }

  void triggerCryptoEvent() {
    onCryptoEventAvailable();
  }

  auto& writeLooper() {
    return writeLooper_;
  }

  auto& readLooper() {
    return readLooper_;
  }

  void registerKnobParamHandler(
      uint64_t paramId,
      std::function<void(QuicServerConnectionState*, uint64_t)>&& handler) {
    registerTransportKnobParamHandler(paramId, std::move(handler));
  }

  void handleKnobParams(const TransportKnobParams& params) {
    handleTransportKnobParams(params);
  }
};

class QuicServerTransportTest : public Test {
 public:
  void SetUp() override {
    clientAddr = folly::SocketAddress("127.0.0.1", 1000);
    serverAddr = folly::SocketAddress("1.2.3.4", 8080);
    clientConnectionId = getTestConnectionId();
    initialDestinationConnectionId = clientConnectionId;
    // change the initialDestinationConnectionId to be different
    // to suss out bugs.
    initialDestinationConnectionId->data()[0] ^= 0x1;
    // set server chosen connId with processId = 0 and workerId = 1
    ServerConnectionIdParams params(0, 0, 1);
    auto sock =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb);
    socket = sock.get();
    EXPECT_CALL(*sock, write(_, _))
        .WillRepeatedly(Invoke([&](const SocketAddress&,
                                   const std::unique_ptr<folly::IOBuf>& buf) {
          serverWrites.push_back(buf->clone());
          return buf->computeChainDataLength();
        }));
    EXPECT_CALL(*sock, address()).WillRepeatedly(ReturnRef(serverAddr));
    supportedVersions = {QuicVersion::MVFST, QuicVersion::QUIC_DRAFT};
    serverCtx = createServerCtx();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    ccFactory_ = std::make_shared<ServerCongestionControllerFactory>();
    server = std::make_shared<TestingQuicServerTransport>(
        &evb, std::move(sock), connCallback, serverCtx);
    server->setCongestionControllerFactory(ccFactory_);
    server->setRoutingCallback(&routingCallback);
    server->setSupportedVersions(supportedVersions);
    server->setOriginalPeerAddress(clientAddr);
    server->setServerConnectionIdParams(params);
    server->getNonConstConn().transportSettings.statelessResetTokenSecret =
        getRandSecret();
    transportInfoCb_ = std::make_unique<NiceMock<MockQuicStats>>();
    server->setTransportStatsCallback(transportInfoCb_.get());
    initializeServerHandshake();
    server->getNonConstConn().handshakeLayer.reset(fakeHandshake);
    server->getNonConstConn().serverHandshakeLayer = fakeHandshake;
    // Allow ignoring path mtu for testing negotiation.
    server->getNonConstConn().transportSettings.canIgnorePathMTU =
        getCanIgnorePathMTU();
    server->getNonConstConn().transportSettings.disableMigration =
        getDisableMigration();
    server->setConnectionIdAlgo(connIdAlgo_.get());
    server->setClientConnectionId(*clientConnectionId);
    server->setClientChosenDestConnectionId(*initialDestinationConnectionId);
    VLOG(20) << __func__ << " client connId=" << clientConnectionId->hex()
             << ", server connId="
             << (server->getConn().serverConnectionId
                     ? server->getConn().serverConnectionId->hex()
                     : " (n/a)");
    server->accept();
    setupConnection();
    EXPECT_TRUE(server->idleTimeout().isScheduled());
    EXPECT_EQ(server->getConn().peerConnectionIds.size(), 1);
    EXPECT_EQ(
        *server->getConn().clientConnectionId,
        server->getConn().peerConnectionIds[0].connId);
  }

  std::shared_ptr<FizzServerQuicHandshakeContext> getFizzServerContext() {
    if (!fizzServerContext) {
      fizzServerContext = FizzServerQuicHandshakeContext::Builder()
                              .setFizzServerContext(createServerCtx())
                              .build();
    }

    return fizzServerContext;
  }

  virtual void initializeServerHandshake() {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(), getFizzServerContext());
  }

  virtual bool getDisableMigration() {
    return true;
  }

  virtual bool getCanIgnorePathMTU() {
    return true;
  }

  std::unique_ptr<Aead> getInitialCipher(
      QuicVersion version = QuicVersion::MVFST) {
    FizzCryptoFactory cryptoFactory;
    return cryptoFactory.getClientInitialCipher(
        *initialDestinationConnectionId, version);
  }

  std::unique_ptr<PacketNumberCipher> getInitialHeaderCipher(
      QuicVersion version = QuicVersion::MVFST) {
    FizzCryptoFactory cryptoFactory;
    return cryptoFactory.makeClientInitialHeaderCipher(
        *initialDestinationConnectionId, version);
  }

  Buf recvEncryptedStream(
      StreamId streamId,
      folly::IOBuf& data,
      uint64_t offset = 0,
      bool eof = false) {
    PacketNum packetNum = clientNextAppDataPacketNum++;
    auto packetData = packetToBuf(createStreamPacket(
        clientConnectionId.value_or(getTestConnectionId()),
        *server->getConn().serverConnectionId,
        packetNum,
        streamId,
        data,
        0 /* cipherOverhead */,
        0 /* largestAcked */,
        folly::none /* longHeaderOverride */,
        eof,
        folly::none,
        offset));
    deliverData(packetData->clone());
    return packetData;
  }

  void recvClientHello(
      bool writes = true,
      QuicVersion version = QuicVersion::MVFST) {
    auto chlo = IOBuf::copyBuffer("CHLO");
    auto nextPacketNum = clientNextInitialPacketNum++;
    auto aead = getInitialCipher(version);
    auto headerCipher = getInitialHeaderCipher(version);
    auto initialPacket = packetToBufCleartext(
        createInitialCryptoPacket(
            *clientConnectionId,
            *initialDestinationConnectionId,
            nextPacketNum,
            version,
            *chlo,
            *aead,
            0 /* largestAcked */),
        *aead,
        *headerCipher,
        nextPacketNum);
    deliverData(initialPacket->clone(), writes);
  }

  void recvClientFinished(
      bool writes = true,
      folly::SocketAddress* peerAddress = nullptr,
      QuicVersion version = QuicVersion::MVFST) {
    auto finished = IOBuf::copyBuffer("FINISHED");
    auto nextPacketNum = clientNextHandshakePacketNum++;
    auto headerCipher = test::createNoOpHeaderCipher();
    uint64_t offset =
        getCryptoStream(
            *server->getConn().cryptoState, EncryptionLevel::Handshake)
            ->currentReadOffset;
    auto handshakeCipher = test::createNoOpAead();
    auto finishedPacket = packetToBufCleartext(
        createCryptoPacket(
            *clientConnectionId,
            *server->getConn().serverConnectionId,
            nextPacketNum,
            version,
            ProtectionType::Handshake,
            *finished,
            *handshakeCipher,
            0 /* largestAcked */,
            offset),
        *handshakeCipher,
        *headerCipher,
        nextPacketNum);
    deliverData(finishedPacket->clone(), writes, peerAddress);
  }

  virtual void setupClientReadCodec() {
    FizzCryptoFactory cryptoFactory;
    clientReadCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
    clientReadCodec->setClientConnectionId(*clientConnectionId);
    clientReadCodec->setInitialReadCipher(cryptoFactory.getServerInitialCipher(
        *initialDestinationConnectionId, QuicVersion::MVFST));
    clientReadCodec->setInitialHeaderCipher(
        cryptoFactory.makeServerInitialHeaderCipher(
            *initialDestinationConnectionId, QuicVersion::MVFST));
    clientReadCodec->setCodecParameters(
        CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  }

  virtual void expectWriteNewSessionTicket() {
    server->setEarlyDataAppParamsFunctions(
        [](const folly::Optional<std::string>&, const Buf&) { return false; },
        []() -> Buf {
          // This function shouldn't be called
          EXPECT_TRUE(false);
          return nullptr;
        });
    EXPECT_CALL(*getFakeHandshakeLayer(), writeNewSessionTicket(_)).Times(0);
  }

  virtual void setupConnection() {
    EXPECT_EQ(server->getConn().readCodec, nullptr);
    EXPECT_EQ(server->getConn().statsCallback, transportInfoCb_.get());
    setupClientReadCodec();
    recvClientHello();

    IOBufEqualTo eq;
    EXPECT_TRUE(eq(getCryptoStreamData(), IOBuf::copyBuffer("SHLO")));
    serverWrites.clear();

    EXPECT_NE(server->getConn().readCodec, nullptr);
    EXPECT_NE(server->getConn().initialWriteCipher, nullptr);
    EXPECT_NE(server->getConn().initialHeaderCipher, nullptr);
    EXPECT_NE(server->getConn().handshakeWriteCipher, nullptr);
    EXPECT_NE(server->getConn().handshakeWriteHeaderCipher, nullptr);
    EXPECT_NE(server->getConn().readCodec->getHandshakeHeaderCipher(), nullptr);

    EXPECT_FALSE(server->getConn().localConnectionError.has_value());
    EXPECT_EQ(server->getConn().version, QuicVersion::MVFST);
    EXPECT_EQ(server->getConn().serverConnIdParams->processId, 0);
    EXPECT_EQ(server->getConn().serverConnIdParams->workerId, 1);
    EXPECT_TRUE(server->getConn().serverConnectionId.has_value());
    EXPECT_EQ(server->getConn().selfConnectionIds.size(), 1);
    serverConnectionId = *server->getConn().serverConnectionId;
    EXPECT_EQ(
        server->getConn().selfConnectionIds[0].connId, serverConnectionId);
    // the crypto data should have been written in the previous loop, verify
    // that the write loop callback is not scheduled any more since we don't
    // have keys to write acks. This assumes that we will schedule crypto data
    // as soon as we can.
    EXPECT_FALSE(server->writeLooper()->isLoopCallbackScheduled());
    EXPECT_FALSE(server->readLooper()->isLoopCallbackScheduled());

    expectWriteNewSessionTicket();
    // Once oneRtt keys are available, ServerTransport must call the
    // onConnectionIdBound on its 'routingCallback'
    EXPECT_CALL(routingCallback, onConnectionIdBound(_))
        .WillOnce(Invoke([&, clientAddr = clientAddr](auto transport) {
          EXPECT_EQ(clientAddr, transport->getOriginalPeerAddress());
        }));

    EXPECT_TRUE(server->getConn().pendingEvents.frames.empty());
    EXPECT_EQ(server->getConn().nextSelfConnectionIdSequence, 1);
    recvClientFinished();

    // We need an extra pump here for some reason.
    loopForWrites();

    // Issue (kMinNumAvailableConnIds - 1) more connection ids on handshake
    // complete
    auto numNewConnIdFrames = 0;
    for (const auto& packet : server->getConn().outstandings.packets) {
      for (const auto& frame : packet.packet.frames) {
        switch (frame.type()) {
          case QuicWriteFrame::Type::QuicSimpleFrame: {
            const auto writeFrame = frame.asQuicSimpleFrame();
            if (writeFrame->type() ==
                QuicSimpleFrame::Type::NewConnectionIdFrame) {
              ++numNewConnIdFrames;
            }
            break;
          }
          default:
            break;
        }
      }
    }
    uint64_t connIdsToIssue = std::min(
                                  server->getConn().peerActiveConnectionIdLimit,
                                  kDefaultActiveConnectionIdLimit) -
        1;

    if (server->getConn().transportSettings.disableMigration ||
        (connIdsToIssue == 0)) {
      EXPECT_EQ(numNewConnIdFrames, 0);
      EXPECT_EQ(server->getConn().nextSelfConnectionIdSequence, 1);
    } else {
      EXPECT_EQ(numNewConnIdFrames, connIdsToIssue);
      EXPECT_EQ(
          server->getConn().nextSelfConnectionIdSequence, connIdsToIssue + 1);
    }

    EXPECT_NE(server->getConn().readCodec, nullptr);
    EXPECT_NE(server->getConn().oneRttWriteCipher, nullptr);
    EXPECT_NE(server->getConn().oneRttWriteHeaderCipher, nullptr);
    EXPECT_NE(server->getConn().readCodec->getOneRttHeaderCipher(), nullptr);

    EXPECT_TRUE(getCryptoStream(
                    *server->getConn().cryptoState, EncryptionLevel::Initial)
                    ->readBuffer.empty());
    EXPECT_FALSE(server->getConn().localConnectionError.has_value());
    verifyTransportParameters(kDefaultIdleTimeout);
    serverWrites.clear();

    auto& cryptoState = server->getConn().cryptoState;
    EXPECT_EQ(cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
    EXPECT_EQ(cryptoState->oneRttStream.retransmissionBuffer.size(), 0);
  }

  void verifyTransportParameters(std::chrono::milliseconds idleTimeout) {
    EXPECT_EQ(server->getConn().peerIdleTimeout, idleTimeout);
    if (getCanIgnorePathMTU()) {
      EXPECT_EQ(
          server->getConn().udpSendPacketLen, fakeHandshake->maxRecvPacketSize);
    }
  }

  void deliverDataWithoutErrorCheck(
      Buf data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    data->coalesce();
    server->onNetworkData(
        peer == nullptr ? clientAddr : *peer,
        NetworkData(std::move(data), Clock::now()));
    if (writes) {
      loopForWrites();
    }
  }

  void deliverData(
      Buf data,
      bool writes = true,
      folly::SocketAddress* peer = nullptr) {
    deliverDataWithoutErrorCheck(std::move(data), writes, peer);
    if (server->getConn().localConnectionError) {
      bool idleTimeout = false;
      const LocalErrorCode* localError =
          server->getConn().localConnectionError->first.asLocalErrorCode();
      if (localError) {
        idleTimeout = (*localError == LocalErrorCode::IDLE_TIMEOUT);
      }
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(server->getConn().localConnectionError->first));
      }
    }
  }

  void loopForWrites() {
    evb.loopOnce(EVLOOP_NONBLOCK);
  }

  Buf getCryptoStreamData() {
    CHECK(!serverWrites.empty());
    auto cryptoBuf = IOBuf::create(0);
    AckStates ackStates;
    for (auto& serverWrite : serverWrites) {
      auto packetQueue = bufToQueue(serverWrite->clone());
      auto result = clientReadCodec->parsePacket(packetQueue, ackStates);
      auto& parsedPacket = *result.regularPacket();
      for (auto& frame : parsedPacket.frames) {
        if (frame.type() != QuicFrame::Type::ReadCryptoFrame) {
          continue;
        }
        cryptoBuf->prependChain(frame.asReadCryptoFrame()->data->clone());
      }
    }
    return cryptoBuf;
  }

  std::unique_ptr<QuicReadCodec> makeClientEncryptedCodec(
      bool handshakeCipher = false) {
    FizzCryptoFactory cryptoFactory;
    auto readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
    readCodec->setOneRttReadCipher(test::createNoOpAead());
    readCodec->setOneRttHeaderCipher(test::createNoOpHeaderCipher());
    readCodec->setHandshakeReadCipher(test::createNoOpAead());
    readCodec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher());
    readCodec->setClientConnectionId(*clientConnectionId);
    readCodec->setCodecParameters(
        CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
    if (handshakeCipher) {
      readCodec->setInitialReadCipher(cryptoFactory.getServerInitialCipher(
          *initialDestinationConnectionId, QuicVersion::MVFST));
      readCodec->setInitialHeaderCipher(
          cryptoFactory.makeServerInitialHeaderCipher(
              *initialDestinationConnectionId, QuicVersion::MVFST));
    }
    return readCodec;
  }

  FakeServerHandshake* getFakeHandshakeLayer() {
    return CHECK_NOTNULL(dynamic_cast<FakeServerHandshake*>(
        server->getNonConstConn().handshakeLayer.get()));
  }

  void checkTransportStateUpdate(
      const std::shared_ptr<FileQLogger>& qLogger,
      const std::string& msg) {
    std::vector<int> indices =
        getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
    EXPECT_EQ(indices.size(), 1);
    auto tmp = std::move(qLogger->logs[indices[0]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, getPeerClose(msg));
  }

  EventBase evb;
  SocketAddress serverAddr;
  SocketAddress clientAddr;
  NiceMock<MockConnectionCallback> connCallback;
  NiceMock<MockRoutingCallback> routingCallback;
  folly::Optional<ConnectionId> clientConnectionId;
  folly::Optional<ConnectionId> initialDestinationConnectionId;
  folly::Optional<ConnectionId> serverConnectionId;
  std::unique_ptr<QuicReadCodec> clientReadCodec;
  std::vector<Buf> serverWrites;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;

  std::vector<QuicVersion> supportedVersions;
  std::unique_ptr<MockQuicStats> transportInfoCb_;
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  std::shared_ptr<CongestionControllerFactory> ccFactory_;
  std::shared_ptr<TestingQuicServerTransport> server;
  folly::test::MockAsyncUDPSocket* socket;
  FakeServerHandshake* fakeHandshake{nullptr};
  std::shared_ptr<FizzServerQuicHandshakeContext> fizzServerContext;
  PacketNum clientNextInitialPacketNum{0}, clientNextHandshakePacketNum{0},
      clientNextAppDataPacketNum{0};
};

TEST_F(QuicServerTransportTest, TestReadMultipleStreams) {
  PacketNum clientPacketNum = clientNextAppDataPacketNum++;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientPacketNum);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  auto buf1 = IOBuf::copyBuffer("Aloha");
  auto buf2 = IOBuf::copyBuffer("Hello");

  auto dataLen = writeStreamFrameHeader(
      builder,
      0x08,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      true,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, buf1->computeChainDataLength());
  writeStreamFrameData(builder, buf1->clone(), buf1->computeChainDataLength());

  dataLen = writeStreamFrameHeader(
      builder,
      0x0C,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      true,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen);
  ASSERT_EQ(*dataLen, buf1->computeChainDataLength());
  writeStreamFrameData(builder, buf2->clone(), buf2->computeChainDataLength());

  auto packet = std::move(builder).buildPacket();

  // Clear out the existing acks to make sure that we are the cause of the acks.
  server->getNonConstConn().ackStates.initialAckState.acks.clear();
  server->getNonConstConn().ackStates.initialAckState.largestRecvdPacketTime =
      folly::none;
  server->getNonConstConn().ackStates.handshakeAckState.acks.clear();
  server->getNonConstConn().ackStates.handshakeAckState.largestRecvdPacketTime =
      folly::none;
  server->getNonConstConn().ackStates.appDataAckState.acks.clear();
  server->getNonConstConn().ackStates.appDataAckState.largestRecvdPacketTime =
      folly::none;

  EXPECT_CALL(*transportInfoCb_, onNewQuicStream()).Times(2); // for x08, x0C
  deliverData(packetToBuf(packet));

  EXPECT_TRUE(
      server->getConn()
          .ackStates.appDataAckState.largestRecvdPacketTime.has_value());
  EXPECT_EQ(server->getConn().ackStates.appDataAckState.acks.size(), 1);
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.acks.front().start,
      clientPacketNum);
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.acks.front().end,
      clientPacketNum);
  ASSERT_EQ(server->getConn().streamManager->streamCount(), 2);
  IOBufEqualTo eq;

  auto stream = server->getNonConstConn().streamManager->findStream(0x08);
  ASSERT_TRUE(stream);
  auto streamData = readDataFromQuicStream(*stream);
  EXPECT_TRUE(eq(buf1, streamData.first));
  EXPECT_TRUE(streamData.second);

  auto stream2 = server->getNonConstConn().streamManager->findStream(0x0C);
  ASSERT_TRUE(stream2);
  auto streamData2 = readDataFromQuicStream(*stream2);
  EXPECT_TRUE(eq(buf2, streamData2.first));
  EXPECT_TRUE(streamData2.second);
  EXPECT_CALL(*transportInfoCb_, onQuicStreamClosed()).Times(2);
}

TEST_F(QuicServerTransportTest, TestInvalidServerStream) {
  EXPECT_CALL(*transportInfoCb_, onNewQuicStream()).Times(0);
  StreamId streamId = 0x01;
  auto data = IOBuf::copyBuffer("Aloha");
  EXPECT_THROW(recvEncryptedStream(streamId, *data), std::runtime_error);
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAckled */));
  EXPECT_THROW(deliverData(std::move(packetData)), std::runtime_error);
  ASSERT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, IdleTimerResetOnRecvNewData) {
  EXPECT_CALL(*transportInfoCb_, onNewQuicStream()).Times(1);
  StreamId streamId = server->createBidirectionalStream().value();
  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  server->idleTimeout().cancelTimeout();
  ASSERT_FALSE(server->idleTimeout().isScheduled());
  recvEncryptedStream(streamId, *expected);
  ASSERT_TRUE(server->idleTimeout().isScheduled());
  EXPECT_CALL(*transportInfoCb_, onQuicStreamClosed());
}

TEST_F(QuicServerTransportTest, IdleTimerNotResetOnDuplicatePacket) {
  EXPECT_CALL(*transportInfoCb_, onNewQuicStream()).Times(1);
  StreamId streamId = server->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = recvEncryptedStream(streamId, *expected);
  ASSERT_TRUE(server->idleTimeout().isScheduled());

  server->idleTimeout().cancelTimeout();
  ASSERT_FALSE(server->idleTimeout().isScheduled());
  // Try delivering the same packet again
  deliverData(packet->clone(), false);
  ASSERT_FALSE(server->idleTimeout().isScheduled());
  EXPECT_CALL(*transportInfoCb_, onQuicStreamClosed());
}

TEST_F(QuicServerTransportTest, IdleTimerNotResetWhenDataOutstanding) {
  // Clear the receivedNewPacketBeforeWrite flag, since we may reveice from
  // client during the SetUp of the test case.
  server->getNonConstConn().outstandings.packets.clear();
  server->getNonConstConn().receivedNewPacketBeforeWrite = false;
  server->getNonConstConn().outstandings.packets.clear();
  StreamId streamId = server->createBidirectionalStream().value();

  server->idleTimeout().cancelTimeout();
  ASSERT_FALSE(server->idleTimeout().isScheduled());
  server->writeChain(
      streamId,
      IOBuf::copyBuffer("And if the darkness is to keep us apart"),
      false,
      false);
  loopForWrites();
  // It was the first packet
  EXPECT_TRUE(server->idleTimeout().isScheduled());

  // cancel it and write something else. This time idle timer shouldn't set.
  server->idleTimeout().cancelTimeout();
  EXPECT_FALSE(server->idleTimeout().isScheduled());
  server->writeChain(
      streamId,
      IOBuf::copyBuffer("And if the daylight feels like it's a long way off"),
      false,
      false);
  loopForWrites();
  EXPECT_FALSE(server->idleTimeout().isScheduled());
}

TEST_F(QuicServerTransportTest, TimeoutsNotSetAfterClose) {
  StreamId streamId = server->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  server->close(std::make_pair(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      std::string("how about no")));
  server->idleTimeout().cancelTimeout();
  ASSERT_FALSE(server->idleTimeout().isScheduled());

  deliverDataWithoutErrorCheck(packet->clone());
  ASSERT_FALSE(server->idleTimeout().isScheduled());
  ASSERT_FALSE(server->lossTimeout().isScheduled());
  ASSERT_FALSE(server->ackTimeout().isScheduled());
  ASSERT_TRUE(server->drainTimeout().isScheduled());
}

TEST_F(QuicServerTransportTest, InvalidMigrationNoDrain) {
  StreamId streamId = server->createBidirectionalStream().value();

  auto expected = IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  server->close(std::make_pair(
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION),
      std::string("migration disabled")));
  server->idleTimeout().cancelTimeout();
  ASSERT_FALSE(server->idleTimeout().isScheduled());

  deliverDataWithoutErrorCheck(packet->clone());
  ASSERT_FALSE(server->idleTimeout().isScheduled());
  ASSERT_FALSE(server->lossTimeout().isScheduled());
  ASSERT_FALSE(server->ackTimeout().isScheduled());
  ASSERT_FALSE(server->drainTimeout().isScheduled());
}

TEST_F(QuicServerTransportTest, IdleTimeoutExpired) {
  server->idleTimeout().timeoutExpired();

  EXPECT_FALSE(server->idleTimeout().isScheduled());
  EXPECT_TRUE(server->isDraining());
  EXPECT_TRUE(server->isClosed());
  auto serverReadCodec = makeClientEncryptedCodec();
  EXPECT_FALSE(verifyFramePresent(
      serverWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites, *serverReadCodec, QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, RecvDataAfterIdleTimeout) {
  server->idleTimeout().timeoutExpired();

  EXPECT_FALSE(server->idleTimeout().isScheduled());
  EXPECT_TRUE(server->isDraining());
  EXPECT_TRUE(server->isClosed());

  serverWrites.clear();
  StreamId streamId = 11;
  auto expected = IOBuf::copyBuffer("hello");
  recvEncryptedStream(streamId, *expected);
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(true),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, TestCloseConnectionWithError) {
  server->close(std::make_pair(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("stopping")));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, TestCloseConnectionWithNoError) {
  server->close(std::make_pair(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("stopping")));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, TestClientAddressChanges) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  StreamId streamId = 4;
  clientAddr = folly::SocketAddress("127.0.0.1", 2000);
  auto data = IOBuf::copyBuffer("data");
  EXPECT_THROW(
      recvEncryptedStream(streamId, *data, 0, true), std::runtime_error);
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 29);
  EXPECT_EQ(
      event->dropReason,
      QuicTransportStatsCallback::toString(
          PacketDropReason::PEER_ADDRESS_CHANGE));
}

TEST_F(QuicServerTransportTest, TestCloseConnectionWithNoErrorPendingStreams) {
  auto streamId = server->createBidirectionalStream().value();

  server->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();

  AckBlocks acks;
  auto start = getFirstOutstandingPacket(
                   server->getNonConstConn(), PacketNumberSpace::AppData)
                   ->packet.header.getPacketSequenceNum();
  auto end = getLastOutstandingPacket(
                 server->getNonConstConn(), PacketNumberSpace::AppData)
                 ->packet.header.getPacketSequenceNum();
  acks.insert(start, end);
  deliverData(packetToBuf(createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData)));
  server->close(std::make_pair(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("stopping")));

  EXPECT_THROW(
      recvEncryptedStream(streamId, *IOBuf::copyBuffer("hello")),
      std::runtime_error);
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, ReceivePacketAfterLocalError) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  // Deliver a reset to non existent stream to trigger a local conn error
  StreamId streamId = 0x01;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  writeFrame(std::move(rstFrame), builder);
  auto packet = std::move(builder).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  serverWrites.clear();

  ShortHeader header2(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      server->getConn().udpSendPacketLen,
      std::move(header2),
      0 /* largestAcked */);
  builder2.encodePacketHeader();
  RstStreamFrame rstFrame2(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  writeFrame(std::move(rstFrame2), builder2);
  auto packet2 = std::move(builder2).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet2));
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(server->getConn()));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
}

TEST_F(QuicServerTransportTest, ReceiveCloseAfterLocalError) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  // Deliver a reset to non existent stream to trigger a local conn error
  StreamId streamId = 0x01;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  writeFrame(std::move(rstFrame), builder);
  auto packet = std::move(builder).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  serverWrites.clear();

  auto currLargestReceivedPacketNum =
      server->getConn().ackStates.appDataAckState.largestReceivedPacketNum;
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(server->getConn()));

  ShortHeader header2(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      server->getConn().udpSendPacketLen,
      std::move(header2),
      0 /* largestAcked */);
  builder2.encodePacketHeader();
  std::string errMsg = "Mind the gap";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  writeFrame(std::move(connClose), builder2);

  auto packet2 = std::move(builder2).buildPacket();
  deliverDataWithoutErrorCheck(packetToBuf(packet2));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_GT(
      server->getConn().ackStates.appDataAckState.largestReceivedPacketNum,
      currLargestReceivedPacketNum);

  // Deliver the same bad data again
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_LT(
      server->getConn()
          .ackStates.appDataAckState.largestReceivedAtLastCloseSent,
      server->getConn().ackStates.appDataAckState.largestReceivedPacketNum);
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  checkTransportStateUpdate(
      qLogger, "Server closed by peer reason=Mind the gap");
}

TEST_F(QuicServerTransportTest, NoDataExceptCloseProcessedAfterClosing) {
  auto packetNum = clientNextAppDataPacketNum++;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      packetNum);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  auto buf = folly::IOBuf::copyBuffer("hello");
  writeStreamFrameHeader(
      builder,
      4,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      folly::none /* skipLenHint */);
  writeStreamFrameData(builder, buf->clone(), buf->computeChainDataLength());
  std::string errMsg = "Mind the gap";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  writeFrame(std::move(connClose), builder);

  auto packet = std::move(builder).buildPacket();

  server->close(std::make_pair(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("hello")));
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_TRUE(hasNotReceivedNewPacketsSinceLastCloseSent(server->getConn()));
  serverWrites.clear();

  // largestReceivedPacketNum won't be accurate because we will throw
  // before updating the ack state.
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_EQ(
      server->getConn().ackStates.appDataAckState.largestReceivedPacketNum,
      packetNum);
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, TestOpenAckStreamFrame) {
  StreamId streamId = server->createBidirectionalStream().value();

  auto data = IOBuf::copyBuffer("Aloha");

  // Remove any packets that might have been queued.
  server->getNonConstConn().outstandings.packets.clear();
  server->getNonConstConn().outstandings.initialPacketsCount = 0;
  server->getNonConstConn().outstandings.handshakePacketsCount = 0;
  server->writeChain(streamId, data->clone(), false, false);
  loopForWrites();
  server->writeChain(streamId, data->clone(), false, false);
  server->writeChain(streamId, data->clone(), false, false);
  loopForWrites();

  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(server->getConn().outstandings.packets.empty());
  ASSERT_FALSE(stream->retransmissionBuffer.empty());
  // We need more than one packet for this test.
  ASSERT_FALSE(server->getConn().outstandings.packets.empty());

  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();

  PacketNum lastPacketNum =
      getLastOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();

  uint32_t buffersInPacket1 = 0;
  for (size_t i = 0; i < server->getNonConstConn().outstandings.packets.size();
       ++i) {
    auto& packet = server->getNonConstConn().outstandings.packets[i];
    if (packet.packet.header.getPacketNumberSpace() !=
        PacketNumberSpace::AppData) {
      continue;
    }
    PacketNum currentPacket = packet.packet.header.getPacketSequenceNum();
    ASSERT_FALSE(packet.packet.frames.empty());
    for (auto& quicFrame : packet.packet.frames) {
      auto frame = quicFrame.asWriteStreamFrame();
      if (!frame) {
        continue;
      }
      auto it = stream->retransmissionBuffer.find(frame->offset);
      ASSERT_TRUE(it != stream->retransmissionBuffer.end());
      if (currentPacket == packetNum1 && frame->streamId == streamId) {
        buffersInPacket1++;
      }
    }
  }

  auto originalRetransSize = stream->retransmissionBuffer.size();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  EXPECT_EQ(
      stream->retransmissionBuffer.size(),
      originalRetransSize - buffersInPacket1);
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  // Dup ack
  auto packet2 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet2));

  EXPECT_EQ(
      stream->retransmissionBuffer.size(),
      originalRetransSize - buffersInPacket1);
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  AckBlocks acks2 = {{packetNum1, lastPacketNum}};
  auto packet3 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks2,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet3));

  EXPECT_EQ(stream->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  auto empty = IOBuf::create(0);
  server->writeChain(streamId, std::move(empty), true, false);
  loopForWrites();
  ASSERT_FALSE(server->getConn().outstandings.packets.empty());

  PacketNum finPacketNum =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();

  AckBlocks acks3 = {{lastPacketNum, finPacketNum}};
  auto packet4 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks3,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet4));
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicServerTransportTest, RecvRstStreamFrameNonexistClientStream) {
  StreamId streamId = 0x00;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  writeFrame(std::move(rstFrame), builder);
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet));

  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_TRUE(stream->streamReadError.has_value());
}

TEST_F(QuicServerTransportTest, ReceiveRstStreamNonExistentAndOtherFrame) {
  StreamId clientUnidirectional = 0x02;

  // Deliver reset on peer unidirectional stream to close the stream.
  RstStreamFrame rstFrame(
      clientUnidirectional, GenericApplicationErrorCode::UNKNOWN, 0);
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  writeFrame(rstFrame, builder);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  deliverData(std::move(packet));

  auto streamId =
      server->createBidirectionalStream(false /* replaySafe */).value();

  ShortHeader header2(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder2(
      server->getConn().udpSendPacketLen,
      std::move(header2),
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
  deliverData(std::move(packet2));

  auto readData = server->read(streamId, 0);
  ASSERT_TRUE(readData.hasValue());
  ASSERT_NE(readData.value().first, nullptr);
  EXPECT_TRUE(folly::IOBufEqualTo()(*readData.value().first, *data));
}

TEST_F(QuicServerTransportTest, RecvRstStreamFrameNonexistServerStream) {
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  StreamId streamId = 0x01;
  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  writeFrame(std::move(rstFrame), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, RecvRstStreamFrame) {
  clientNextAppDataPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  writeDataToQuicStream(*stream, IOBuf::copyBuffer(words.at(3)), false);
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  RstStreamFrame rstFrame(
      streamId,
      GenericApplicationErrorCode::UNKNOWN,
      words.at(0).length() + words.at(1).length());
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(std::move(rstFrame), builder);
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet));

  // Verify stream receive state is cleaned up but send state isn't:
  auto updatedStream =
      server->getNonConstConn().streamManager->findStream(streamId);
  ASSERT_TRUE(updatedStream);
  EXPECT_TRUE(updatedStream->readBuffer.empty());
  // We can verify retx buffer isn't empty here. The writeBuffer though could be
  // empty since deliverData can cause a write synchrously.
  EXPECT_FALSE(updatedStream->retransmissionBuffer.empty());
  EXPECT_EQ(
      words.at(0).length() + words.at(1).length(),
      updatedStream->finalReadOffset.value());
  // updatedStream still writable since receiving rst has no impact on egress
  EXPECT_TRUE(updatedStream->writable());
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrame) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(QuicSimpleFrame(stopSendingFrame), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(
      connCallback,
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN));
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrameAfterCloseStream) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();
  server->getNonConstConn().flowControlState.sumCurStreamBufferLen = 100;

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(QuicSimpleFrame(stopSendingFrame), builder);
  auto packet = std::move(builder).buildPacket();
  server->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_CALL(connCallback, onStopSending(_, _)).Times(0);
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvInvalidMaxStreamData) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x02;
  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();
  server->getNonConstConn().flowControlState.sumCurStreamBufferLen = 100;

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  MaxStreamDataFrame maxStreamDataFrame(streamId, 100);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(std::move(maxStreamDataFrame), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrameAfterHalfCloseRemote) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId = 0x00;
  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  stream->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  stream->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  auto dataLen = writeStreamFrameHeader(
      builder,
      0x00,
      stream->currentReadOffset,
      0,
      10,
      true,
      folly::none /* skipLenHint */);
  ASSERT_TRUE(dataLen.has_value());
  ASSERT_EQ(*dataLen, 0);
  writeFrame(QuicSimpleFrame(stopSendingFrame), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(
      connCallback,
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN));
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvStopSendingBeforeStream) {
  StreamId streamId = 0x00;
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(QuicSimpleFrame(stopSendingFrame), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(connCallback, onNewBidirectionalStream(streamId));
  EXPECT_CALL(
      connCallback,
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN));
  deliverData(packetToBuf(packet));
}

TEST_F(QuicServerTransportTest, RecvStopSendingFrameAfterReset) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  std::array<std::string, 4> words = {
      "Hey Bob, this is Alice, for real.",
      "What message did I send you last time?",
      "You don't sound like Alice",
      "You are a liar!",
  };

  StreamId streamId1 = 0x00;
  StreamId streamId2 = 0x04;
  auto stream1 = server->getNonConstConn().streamManager->getStream(streamId1);
  stream1->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream1->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream1->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  stream1->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream1->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream1->currentReadOffset = words.at(0).length() + words.at(1).length();
  auto stream2 = server->getNonConstConn().streamManager->getStream(streamId2);
  stream2->readBuffer.emplace_back(IOBuf::copyBuffer(words.at(0)), 0, false);
  stream2->readBuffer.emplace_back(
      IOBuf::copyBuffer(words.at(1)), words.at(0).length(), false);
  stream2->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          IOBuf::copyBuffer(words.at(2)), 0, false)));
  stream2->writeBuffer.append(IOBuf::copyBuffer(words.at(3)));
  stream2->currentWriteOffset = words.at(2).length() + words.at(3).length();
  stream2->currentReadOffset = words.at(0).length() + words.at(1).length();

  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 5;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  StopSendingFrame stopSendingFrame1(
      streamId1, GenericApplicationErrorCode::UNKNOWN);
  StopSendingFrame stopSendingFrame2(
      streamId2, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(QuicSimpleFrame(stopSendingFrame1), builder);
  writeFrame(QuicSimpleFrame(stopSendingFrame2), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(
      connCallback, onStopSending(_, GenericApplicationErrorCode::UNKNOWN))
      .WillOnce(Invoke([&](StreamId /*sid*/, ApplicationErrorCode /*e*/) {
        server->close(folly::none);
      }));
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

TEST_F(QuicServerTransportTest, StopSendingLoss) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  auto streamId = server->createBidirectionalStream().value();
  server->getNonConstConn().streamManager->getStream(streamId);
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      server->getNonConstConn().ackStates.appDataAckState.nextPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      server->getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(
          0));
  builder.encodePacketHeader();
  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(QuicSimpleFrame(stopSendingFrame), builder);
  auto packet = std::move(builder).buildPacket();
  markPacketLoss(server->getNonConstConn(), packet.packet, false);
  EXPECT_EQ(server->getNonConstConn().pendingEvents.frames.size(), 1);
  StopSendingFrame* stopFrame = server->getNonConstConn()
                                    .pendingEvents.frames.front()
                                    .asStopSendingFrame();
  ASSERT_NE(stopFrame, nullptr);
  EXPECT_EQ(*stopFrame, stopSendingFrame);
}

TEST_F(QuicServerTransportTest, StopSendingLossAfterStreamClosed) {
  server->getNonConstConn().ackStates.appDataAckState.nextPacketNum = 3;
  auto streamId = server->createBidirectionalStream().value();
  server->getNonConstConn().streamManager->getStream(streamId);
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      server->getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(
          0));
  builder.encodePacketHeader();
  StopSendingFrame stopSendingFrame(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(builder.canBuildPacket());
  writeFrame(QuicSimpleFrame(stopSendingFrame), builder);
  auto packet = std::move(builder).buildPacket();

  // clear out all the streams, this is not a great way to simulate closed
  // streams, but good enough for this test.
  server->getNonConstConn().streamManager->clearOpenStreams();
  markPacketLoss(server->getNonConstConn(), packet.packet, false);
  EXPECT_EQ(server->getNonConstConn().pendingEvents.frames.size(), 0);
}

TEST_F(QuicServerTransportTest, TestCloneStopSending) {
  auto streamId = server->createBidirectionalStream().value();
  auto qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().streamManager->getStream(streamId);
  // knock every handshake outstanding packets out
  server->getNonConstConn().outstandings.initialPacketsCount = 0;
  server->getNonConstConn().outstandings.handshakePacketsCount = 0;
  server->getNonConstConn().outstandings.packets.clear();
  for (auto& t : server->getNonConstConn().lossState.lossTimes) {
    t.reset();
  }

  server->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  // Find the outstanding StopSending.
  auto packetItr = std::find_if(
      server->getNonConstConn().outstandings.packets.begin(),
      server->getNonConstConn().outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::StopSendingFrame>());

  ASSERT_TRUE(
      packetItr != server->getNonConstConn().outstandings.packets.end());
  // Force a timeout with no data so that it clones the packet
  server->lossTimeout().timeoutExpired();
  loopForWrites();
  auto numStopSendingPackets = std::count_if(
      server->getNonConstConn().outstandings.packets.begin(),
      server->getNonConstConn().outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::StopSendingFrame>());

  EXPECT_GT(numStopSendingPackets, 1);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, kLossTimeoutExpired);
}

TEST_F(QuicServerTransportTest, TestAckStopSending) {
  auto streamId = server->createBidirectionalStream().value();
  server->getNonConstConn().streamManager->getStream(streamId);
  server->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  auto match = findFrameInPacketFunc<QuicSimpleFrame::Type::StopSendingFrame>();

  auto op = findOutstandingPacket(server->getNonConstConn(), match);
  ASSERT_TRUE(op != nullptr);
  PacketNum packetNum = op->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum, packetNum}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  op = findOutstandingPacket(server->getNonConstConn(), match);
  EXPECT_TRUE(op == nullptr);
}

TEST_F(QuicServerTransportTest, RecvPathChallenge) {
  auto& conn = server->getNonConstConn();

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(ConnectionId({1, 2, 3, 4}), 1);

  ShortHeader header(
      ProtectionType::KeyPhaseZero, *conn.serverConnectionId, 10);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  PathChallengeFrame pathChallenge(123);
  ASSERT_TRUE(builder.canBuildPacket());
  writeSimpleFrame(QuicSimpleFrame(pathChallenge), builder);

  auto packet = std::move(builder).buildPacket();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 2);
  // The RetireConnectionId frame will be enqueued before the PathResponse.
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 0);

  PathResponseFrame& pathResponse =
      *conn.pendingEvents.frames[1].asPathResponseFrame();
  EXPECT_EQ(pathResponse.pathData, pathChallenge.pathData);
}

TEST_F(QuicServerTransportTest, TestAckRstStream) {
  auto streamId = server->createUnidirectionalStream().value();
  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  auto packetNum = rstStreamAndSendPacket(
      server->getNonConstConn(),
      server->getSocket(),
      *stream,
      GenericApplicationErrorCode::UNKNOWN);

  AckBlocks acks = {{packetNum, packetNum}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  // Closed streams should be deleted.
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, ReceiveConnectionClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  std::string errMsg = "Stand clear of the closing doors, please";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  writeFrame(std::move(connClose), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(connCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  // Now the transport should be closed
  EXPECT_EQ(
      server->getConn().localConnectionError->first,
      QuicErrorCode(TransportErrorCode::NO_ERROR));
  EXPECT_EQ(
      server->getConn().peerConnectionError->first,
      QuicErrorCode(TransportErrorCode::NO_ERROR));
  auto closedMsg =
      folly::to<std::string>("Server closed by peer reason=", errMsg);
  EXPECT_EQ(server->getConn().peerConnectionError->second, closedMsg);
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  checkTransportStateUpdate(qLogger, std::move(closedMsg));
}

TEST_F(QuicServerTransportTest, ReceiveApplicationClose) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();

  std::string errMsg = "Stand clear of the closing doors, please";
  ConnectionCloseFrame appClose(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN), errMsg);
  writeFrame(std::move(appClose), builder);
  auto packet = std::move(builder).buildPacket();

  EXPECT_CALL(
      connCallback,
      onConnectionError(IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      server->getConn().localConnectionError->first);
  EXPECT_EQ(
      server->getConn().peerConnectionError->first,
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN));
  auto closedMsg =
      folly::to<std::string>("Server closed by peer reason=", errMsg);
  EXPECT_EQ(server->getConn().peerConnectionError->second, closedMsg);
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  checkTransportStateUpdate(qLogger, std::move(closedMsg));
}

TEST_F(QuicServerTransportTest, ReceiveConnectionCloseTwice) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  std::string errMsg = "Mind the gap";
  ConnectionCloseFrame connClose(
      QuicErrorCode(TransportErrorCode::NO_ERROR), errMsg);
  writeFrame(std::move(connClose), builder);
  auto packet = std::move(builder).buildPacket();
  EXPECT_CALL(connCallback, onConnectionEnd());
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  // Now the transport should be closed
  EXPECT_EQ(
      QuicErrorCode(TransportErrorCode::NO_ERROR),
      server->getConn().localConnectionError->first);
  EXPECT_EQ(
      server->getConn().peerConnectionError->first,
      QuicErrorCode(TransportErrorCode::NO_ERROR));
  auto closedMsg =
      folly::to<std::string>("Server closed by peer reason=", errMsg);
  EXPECT_EQ(server->getConn().peerConnectionError->second, closedMsg);
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  serverWrites.clear();
  deliverDataWithoutErrorCheck(packetToBuf(packet));
  EXPECT_FALSE(verifyFramePresent(
      serverWrites,
      *makeClientEncryptedCodec(),
      QuicFrame::Type::ConnectionCloseFrame));
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 29);
  EXPECT_EQ(
      event->dropReason,
      QuicTransportStatsCallback::toString(
          PacketDropReason::SERVER_STATE_CLOSED));
}

TEST_F(QuicServerTransportTest, CloseTransportWontUnbound) {
  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _)).Times(0);
  server->closeTransport();
  // Need to do this otherwise server transport destructor will still call
  // onConnectionUnbound
  server->setRoutingCallback(nullptr);
}

TEST_F(QuicServerTransportTest, UnboundConnection) {
  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _)).Times(1);
  server->unbindConnection();
  // Need to do this otherwise server transport destructor will still call
  // onConnectionUnbound
  server->setRoutingCallback(nullptr);
}

TEST_F(QuicServerTransportTest, DestroyWithoutClosing) {
  StreamId streamId = server->createBidirectionalStream().value();

  MockReadCallback readCb;
  server->setReadCallback(streamId, &readCb);

  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  MockDeliveryCallback deliveryCallback;
  auto write = IOBuf::copyBuffer("no");
  server->writeChain(streamId, write->clone(), true, false, &deliveryCallback);

  EXPECT_CALL(deliveryCallback, onCanceled(_, _));
  EXPECT_CALL(readCb, readError(_, _));

  server.reset();
}

TEST_F(QuicServerTransportTest, DestroyWithoutClosingCancelByteEvents) {
  StreamId streamId = server->createBidirectionalStream().value();

  MockReadCallback readCb;
  server->setReadCallback(streamId, &readCb);

  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  auto write = IOBuf::copyBuffer("no");
  server->writeChain(streamId, write->clone(), true, false);

  MockByteEventCallback txCallback;
  MockByteEventCallback deliveryCallback;

  server->registerByteEventCallback(
      ByteEvent::Type::TX, streamId, 0, &txCallback);
  server->registerByteEventCallback(
      ByteEvent::Type::ACK, streamId, 0, &deliveryCallback);

  EXPECT_CALL(txCallback, onByteEventCanceled(_));
  EXPECT_CALL(deliveryCallback, onByteEventCanceled(_));
  EXPECT_CALL(readCb, readError(_, _));

  server.reset();
}

TEST_F(QuicServerTransportTest, SetCongestionControl) {
  // Default: Cubic
  auto cc = server->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());

  // Change to Reno
  server->setCongestionControl(CongestionControlType::NewReno);
  cc = server->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::NewReno, cc->type());

  // Change back to Cubic:
  server->setCongestionControl(CongestionControlType::Cubic);
  cc = server->getConn().congestionController.get();
  EXPECT_EQ(CongestionControlType::Cubic, cc->type());
}

TEST_F(QuicServerTransportTest, TestServerNotDetachable) {
  EXPECT_FALSE(server->isDetachable());
}

TEST_F(QuicServerTransportTest, SetOriginalPeerAddressSetsPacketSize) {
  folly::SocketAddress v4Address("0.0.0.0", 0);
  ASSERT_TRUE(v4Address.getFamily() == AF_INET);
  server->setOriginalPeerAddress(v4Address);
  EXPECT_EQ(kDefaultV4UDPSendPacketLen, server->getConn().udpSendPacketLen);

  folly::SocketAddress v6Address("::", 0);
  ASSERT_TRUE(v6Address.getFamily() == AF_INET6);
  server->setOriginalPeerAddress(v6Address);
  EXPECT_EQ(kDefaultV6UDPSendPacketLen, server->getConn().udpSendPacketLen);

  server->closeNow(folly::none);
}

TEST_F(
    QuicServerTransportTest,
    ReceiveDataFromChangedPeerAddressWhileMigrationIsDisabled) {
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  try {
    deliverData(std::move(packetData), true, &newPeer);
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second, "Migration disabled");
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicServerTransportTest, SwitchServerCidsNoOtherIds) {
  auto& conn = server->getNonConstConn();

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicServerTransportTest, SwitchServerCidsOneOtherCid) {
  auto& conn = server->getNonConstConn();
  auto originalCid = conn.clientConnectionId;
  auto secondCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{5, 6, 7, 8}), 2);
  conn.peerConnectionIds.push_back(secondCid);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 0);

  auto replacedCid = conn.clientConnectionId;
  EXPECT_NE(originalCid, *replacedCid);
  EXPECT_EQ(secondCid.connId, *replacedCid);
}

TEST_F(QuicServerTransportTest, SwitchServerCidsMultipleCids) {
  auto& conn = server->getNonConstConn();
  auto originalCid = conn.clientConnectionId;
  auto secondCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{5, 6, 7, 8}), 2);
  auto thirdCid =
      ConnectionIdData(ConnectionId(std::vector<uint8_t>{3, 3, 3, 3}), 3);

  conn.peerConnectionIds.push_back(secondCid);
  conn.peerConnectionIds.push_back(thirdCid);

  EXPECT_EQ(conn.retireAndSwitchPeerConnectionIds(), true);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);

  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  auto retireFrame = conn.pendingEvents.frames[0].asRetireConnectionIdFrame();
  EXPECT_EQ(retireFrame->sequenceNumber, 0);

  // Uses the first unused connection id.
  auto replacedCid = conn.clientConnectionId;
  EXPECT_NE(originalCid, *replacedCid);
  EXPECT_EQ(secondCid.connId, *replacedCid);
}

class QuicServerTransportAllowMigrationTest
    : public QuicServerTransportTest,
      public WithParamInterface<MigrationParam> {
 public:
  bool getDisableMigration() override {
    return false;
  }

  virtual void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        false,
        false,
        GetParam().clientSentActiveConnIdTransportParam);
  }
};

INSTANTIATE_TEST_CASE_P(
    QuicServerTransportMigrationTests,
    QuicServerTransportAllowMigrationTest,
    Values(
        MigrationParam{folly::none},
        MigrationParam{2},
        MigrationParam{4},
        MigrationParam{9},
        MigrationParam{50}));

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbingPacketFromChangedPeerAddress) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.disableMigration = false;

  // Add additional peer id so PathResponse completes.
  server->getNonConstConn().peerConnectionIds.emplace_back(
      ConnectionId({1, 2, 3, 4}), 1);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  writeSimpleFrame(PathChallengeFrame(123), builder);
  auto packet = std::move(builder).buildPacket();
  auto packetData = packetToBuf(packet);
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  try {
    deliverData(std::move(packetData), true, &newPeer);
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second,
      "Probing not supported yet");

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 29);
  EXPECT_EQ(
      event->dropReason,
      QuicTransportStatsCallback::toString(
          PacketDropReason::PEER_ADDRESS_CHANGE));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveReorderedDataFromChangedPeerAddress) {
  auto data = IOBuf::copyBuffer("bad data");
  auto firstPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto secondPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Receive second packet first
  deliverData(std::move(secondPacket));

  auto peerAddress = server->getConn().peerAddress;

  // Receive first packet later from a different address
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(firstPacket), true, &newPeer);

  // No migration for reordered packet
  EXPECT_EQ(server->getConn().peerAddress, peerAddress);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToUnvalidatedPeer) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());

  EXPECT_TRUE(server->getConn().pathValidationLimiter != nullptr);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  writeSimpleFrame(
      PathResponseFrame(server->getConn().outstandingPathValidation->pathData),
      builder);
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());
}

TEST_P(QuicServerTransportAllowMigrationTest, ResetPathRttPathResponse) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  writeSimpleFrame(
      PathResponseFrame(server->getConn().outstandingPathValidation->pathData),
      builder);
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());
  EXPECT_FALSE(server->getConn().writableBytesLimit);

  // After Pathresponse frame is received, srtt,lrtt = sampleRtt;
  // sampleRtt = time from send of PathChallenge to receiving PathResponse
  EXPECT_NE(server->getConn().lossState.srtt, 0us);
  EXPECT_NE(server->getConn().lossState.lrtt, 0us);
  EXPECT_NE(server->getConn().lossState.rttvar, 0us);

  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
}

TEST_P(QuicServerTransportAllowMigrationTest, IgnoreInvalidPathResponse) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;

  folly::SocketAddress newPeer("100.101.102.103", 23456);

  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);

  EXPECT_TRUE(server->getConn().pathValidationLimiter != nullptr);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());

  writeSimpleFrame(
      PathResponseFrame(
          server->getConn().outstandingPathValidation->pathData ^ 1),
      builder);
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceivePathResponseFromDifferentPeerAddress) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);

  auto peerAddress = server->getConn().peerAddress;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);

  loopForWrites();
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());

  EXPECT_TRUE(server->getConn().pathValidationLimiter != nullptr);

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  writeSimpleFrame(
      PathResponseFrame(server->getConn().outstandingPathValidation->pathData),
      builder);
  auto packet = std::move(builder).buildPacket();
  folly::SocketAddress newPeer2("200.101.102.103", 23456);
  try {
    deliverData(packetToBuf(packet), false, &newPeer2);
    FAIL();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->isClosed());
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());

  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second,
      "Probing not supported yet");
}

TEST_F(QuicServerTransportTest, TooManyMigrations) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.disableMigration = false;

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  for (size_t i = 0; i < kMaxNumMigrationsAllowed; ++i) {
    folly::SocketAddress newPeer("100.101.102.103", 23456 + i);
    deliverData(packetData->clone(), false, &newPeer);
  }

  folly::SocketAddress newPeer("200.101.102.103", 23456);
  try {
    deliverData(packetData->clone(), false, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second, "Too many migrations");
  EXPECT_TRUE(server->isClosed());
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 0);
  EXPECT_EQ(
      event->dropReason,
      QuicTransportStatsCallback::toString(
          PacketDropReason::PEER_ADDRESS_CHANGE));
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToValidatedPeer) {
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  server->getNonConstConn().migrationState.previousPeerAddresses.push_back(
      newPeer);
  CongestionAndRttState state;
  state.peerAddress = newPeer;
  state.recordTime = Clock::now();
  state.congestionController = ccFactory_->makeCongestionController(
      server->getNonConstConn(),
      server->getNonConstConn().transportSettings.defaultCongestionController);
  state.srtt = 1000us;
  state.lrtt = 2000us;
  state.rttvar = 3000us;
  state.mrtt = 800us;
  server->getNonConstConn().migrationState.lastCongestionAndRtt =
      std::move(state);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);

  auto peerAddress = server->getConn().peerAddress;
  auto lastCongestionController =
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get();
  auto lastSrtt = server->getConn().migrationState.lastCongestionAndRtt->srtt;
  auto lastLrtt = server->getConn().migrationState.lastCongestionAndRtt->lrtt;
  auto lastRttvar =
      server->getConn().migrationState.lastCongestionAndRtt->rttvar;
  auto lastMrtt = server->getConn().migrationState.lastCongestionAndRtt->mrtt;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, lastSrtt);
  EXPECT_EQ(server->getConn().lossState.lrtt, lastLrtt);
  EXPECT_EQ(server->getConn().lossState.rttvar, lastRttvar);
  EXPECT_EQ(server->getConn().lossState.mrtt, lastMrtt);
  EXPECT_EQ(
      server->getConn().congestionController.get(), lastCongestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrateToUnvalidatedPeerOverwritesCachedRttState) {
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  server->getNonConstConn().migrationState.previousPeerAddresses.push_back(
      newPeer);
  CongestionAndRttState state;
  state.peerAddress = newPeer;
  state.recordTime = Clock::now();
  state.congestionController = ccFactory_->makeCongestionController(
      server->getNonConstConn(),
      server->getNonConstConn().transportSettings.defaultCongestionController);
  state.srtt = 1000us;
  state.lrtt = 2000us;
  state.rttvar = 3000us;
  state.mrtt = 800us;
  server->getNonConstConn().migrationState.lastCongestionAndRtt =
      std::move(state);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer2("200.101.102.103", 2345);
  deliverData(std::move(packetData), false, &newPeer2);

  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);

  EXPECT_EQ(server->getConn().peerAddress, newPeer2);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 2);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.front(), newPeer);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToStaleValidatedPeer) {
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  server->getNonConstConn().migrationState.previousPeerAddresses.push_back(
      newPeer);
  CongestionAndRttState state;
  state.peerAddress = newPeer;
  state.recordTime = Clock::now() - 2 * kTimeToRetainLastCongestionAndRttState;
  state.congestionController = ccFactory_->makeCongestionController(
      server->getNonConstConn(),
      server->getNonConstConn().transportSettings.defaultCongestionController);
  state.srtt = 1000us;
  state.lrtt = 2000us;
  state.rttvar = 3000us;
  state.srtt = 800us;
  server->getNonConstConn().migrationState.lastCongestionAndRtt =
      std::move(state);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_F(
    QuicServerTransportTest,
    MigrateToValidatePeerCancelsPendingPathChallenge) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_TRUE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2), false);
  EXPECT_FALSE(server->getConn().pendingEvents.pathChallenge);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);
  EXPECT_EQ(server->getConn().lossState.srtt, srtt);
  EXPECT_EQ(server->getConn().lossState.lrtt, lrtt);
  EXPECT_EQ(server->getConn().lossState.rttvar, rttvar);
  EXPECT_EQ(server->getConn().lossState.mrtt, mrtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(
    QuicServerTransportTest,
    MigrateToUnvalidatePeerCancelsOutstandingPathChallenge) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  folly::SocketAddress newPeer2("200.101.102.103", 23456);
  deliverData(std::move(packetData2), false, &newPeer2);
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);
}

TEST_F(
    QuicServerTransportTest,
    MigrateToValidatePeerCancelsOutstandingPathChallenge) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto congestionController = server->getConn().congestionController.get();
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;
  auto mrtt = server->getConn().lossState.mrtt;

  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_TRUE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().migrationState.previousPeerAddresses.back(),
      peerAddress);
  EXPECT_EQ(server->getConn().lossState.srtt, 0us);
  EXPECT_EQ(server->getConn().lossState.lrtt, 0us);
  EXPECT_EQ(server->getConn().lossState.rttvar, 0us);
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->peerAddress,
      clientAddr);
  EXPECT_EQ(
      server->getConn()
          .migrationState.lastCongestionAndRtt->congestionController.get(),
      congestionController);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->srtt, srtt);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->lrtt, lrtt);
  EXPECT_EQ(
      server->getConn().migrationState.lastCongestionAndRtt->rttvar, rttvar);
  EXPECT_EQ(server->getConn().migrationState.lastCongestionAndRtt->mrtt, mrtt);

  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2));
  EXPECT_FALSE(server->getConn().outstandingPathValidation);
  EXPECT_FALSE(server->getConn().pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isScheduled());

  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 0);
  EXPECT_EQ(server->getConn().lossState.srtt, srtt);
  EXPECT_EQ(server->getConn().lossState.lrtt, lrtt);
  EXPECT_EQ(server->getConn().lossState.rttvar, rttvar);
  EXPECT_EQ(server->getConn().lossState.mrtt, mrtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(QuicServerTransportTest, ClientPortChangeNATRebinding) {
  server->getNonConstConn().transportSettings.disableMigration = false;

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  server->writeChain(streamId, data1->clone(), false, false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();

  folly::SocketAddress newPeer(clientAddr.getIPAddress(), 23456);
  deliverData(std::move(packetData), true, &newPeer);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);
  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_NE(
      server->getConn().lossState.srtt, std::chrono::microseconds::zero());
  EXPECT_NE(
      server->getConn().lossState.lrtt, std::chrono::microseconds::zero());
  EXPECT_NE(
      server->getConn().lossState.rttvar, std::chrono::microseconds::zero());
  EXPECT_NE(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(QuicServerTransportTest, ClientAddressChangeNATRebinding) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  server->writeChain(streamId, data1->clone(), false, false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();

  folly::SocketAddress newPeer("127.0.0.100", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);

  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_NE(server->getConn().lossState.srtt, 0us);
  EXPECT_NE(server->getConn().lossState.lrtt, 0us);
  EXPECT_NE(server->getConn().lossState.rttvar, 0us);
  EXPECT_NE(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_EQ(server->getConn().congestionController.get(), congestionController);
  EXPECT_FALSE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(
    QuicServerTransportTest,
    ClientNATRebindingWhilePathValidationOutstanding) {
  server->getNonConstConn().transportSettings.disableMigration = false;

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();

  folly::SocketAddress newPeer("200.0.0.100", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);

  EXPECT_EQ(server->getConn().peerAddress, newPeer);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().lossState.srtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.lrtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.rttvar, std::chrono::microseconds::zero());
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_NE(server->getConn().congestionController.get(), nullptr);
  EXPECT_NE(server->getConn().congestionController.get(), congestionController);
  EXPECT_TRUE(server->getConn().migrationState.lastCongestionAndRtt);

  auto newCC = server->getConn().congestionController.get();
  folly::SocketAddress newPeer2("200.0.0.200", 12345);
  auto data2 = IOBuf::copyBuffer("bad data");
  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2), true, &newPeer2);

  EXPECT_TRUE(server->getConn().outstandingPathValidation);

  EXPECT_EQ(server->getConn().peerAddress, newPeer2);
  EXPECT_EQ(server->getConn().migrationState.previousPeerAddresses.size(), 1);
  EXPECT_EQ(
      server->getConn().lossState.srtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.lrtt, std::chrono::microseconds::zero());
  EXPECT_EQ(
      server->getConn().lossState.rttvar, std::chrono::microseconds::zero());
  EXPECT_EQ(server->getConn().lossState.mrtt, kDefaultMinRtt);
  EXPECT_EQ(server->getConn().congestionController.get(), newCC);
  EXPECT_TRUE(server->getConn().migrationState.lastCongestionAndRtt);
}

TEST_F(QuicServerTransportTest, PingIsTreatedAsRetransmittable) {
  PingFrame pingFrame;
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  writeFrame(pingFrame, builder);
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet));
  EXPECT_TRUE(server->getConn().pendingEvents.scheduleAckTimeout);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdValid) {
  auto& conn = server->getNonConstConn();
  conn.transportSettings.selfActiveConnectionIdLimit = 2;

  ShortHeader header(ProtectionType::KeyPhaseZero, *conn.clientConnectionId, 1);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  ASSERT_TRUE(builder.canBuildPacket());
  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId({2, 4, 2, 3}), StatelessResetToken{9, 8, 7, 6});
  writeSimpleFrame(QuicSimpleFrame(newConnId), builder);

  auto packet = std::move(builder).buildPacket();

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_EQ(conn.peerConnectionIds[1].connId, newConnId.connectionId);
  EXPECT_EQ(conn.peerConnectionIds[1].sequenceNumber, newConnId.sequenceNumber);
  EXPECT_EQ(conn.peerConnectionIds[1].token, newConnId.token);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdTooManyReceivedIds) {
  auto& conn = server->getNonConstConn();
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

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdInvalidRetire) {
  auto& conn = server->getNonConstConn();
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

  EXPECT_EQ(conn.peerConnectionIds.size(), 1);
  EXPECT_THROW(deliverData(packetToBuf(packet), false), std::runtime_error);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdNoopValidDuplicate) {
  auto& conn = server->getNonConstConn();
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

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  deliverData(packetToBuf(packet), false);
  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
}

TEST_F(QuicServerTransportTest, RecvNewConnectionIdExceptionInvalidDuplicate) {
  auto& conn = server->getNonConstConn();

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

  EXPECT_EQ(conn.peerConnectionIds.size(), 2);
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
}

class QuicUnencryptedServerTransportTest : public QuicServerTransportTest {
 public:
  void setupConnection() override {}
};

TEST_F(QuicUnencryptedServerTransportTest, FirstPacketProcessedCallback) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  EXPECT_CALL(connCallback, onFirstPeerPacketProcessed()).Times(1);
  recvClientHello();
  loopForWrites();
  AckBlocks acks;
  acks.insert(0);
  auto aead = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  EXPECT_CALL(connCallback, onFirstPeerPacketProcessed()).Times(0);
  deliverData(packetToBufCleartext(
      createAckPacket(
          server->getNonConstConn(),
          clientNextInitialPacketNum,
          acks,
          PacketNumberSpace::Initial,
          aead.get()),
      *aead,
      *headerCipher,
      clientNextInitialPacketNum));
}

TEST_F(QuicUnencryptedServerTransportTest, TestUnencryptedStream) {
  auto data = IOBuf::copyBuffer("bad data");
  PacketNum nextPacket = clientNextInitialPacketNum++;
  StreamId streamId = 3;
  auto initialCipher = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  auto packetData = packetToBufCleartext(
      createStreamPacket(
          *clientConnectionId,
          *initialDestinationConnectionId,
          nextPacket,
          streamId,
          *data,
          initialCipher->getCipherOverhead(),
          0 /* largestAcked */,
          std::make_pair(LongHeader::Types::Initial, QuicVersion::MVFST)),
      *initialCipher,
      *headerCipher,
      nextPacket);
  EXPECT_THROW(deliverData(std::move(packetData)), std::runtime_error);
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
}

TEST_F(QuicUnencryptedServerTransportTest, TestUnencryptedAck) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  AckBlocks acks = {{1, 2}};
  auto expected = IOBuf::copyBuffer("hello");
  PacketNum nextPacketNum = clientNextInitialPacketNum++;
  LongHeader header(
      LongHeader::Types::Initial,
      *clientConnectionId,
      server->getConn().serverConnectionId.value_or(getTestConnectionId(1)),
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  DCHECK(builder.canBuildPacket());
  AckFrameMetaData ackData(acks, 0us, 0);
  writeAckFrame(ackData, builder);
  auto packet = packetToBufCleartext(
      std::move(builder).buildPacket(),
      *getInitialCipher(),
      *getInitialHeaderCipher(),
      nextPacketNum);
  EXPECT_NO_THROW(deliverData(std::move(packet)));
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);

  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 45);
  EXPECT_EQ(event->dropReason, kCipherUnavailable);
}

TEST_F(QuicUnencryptedServerTransportTest, TestBadPacketProtectionLevel) {
  // Version negotiation has no protection level.
  auto packet = VersionNegotiationPacketBuilder(
                    *clientConnectionId /* src */,
                    getTestConnectionId(1) /* dest */,
                    {QuicVersion::MVFST})
                    .buildPacket();
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));
  deliverData(packet.second->clone());
}

TEST_F(QuicUnencryptedServerTransportTest, TestBadCleartextEncryption) {
  FizzCryptoFactory cryptoFactory;
  PacketNum nextPacket = clientNextInitialPacketNum++;
  auto aead = cryptoFactory.getServerInitialCipher(
      *clientConnectionId, QuicVersion::MVFST);
  auto packetData = packetToBufCleartext(
      createInitialCryptoPacket(
          *clientConnectionId,
          *initialDestinationConnectionId,
          nextPacket,
          QuicVersion::MVFST,
          *IOBuf::copyBuffer("CHLO"),
          *aead,
          0 /* largestAcked */),
      *aead,
      *getInitialHeaderCipher(),
      nextPacket);
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));
  deliverData(std::move(packetData));
  // If crypto data was processed, we would have generated some writes.
  EXPECT_NE(server->getConn().readCodec, nullptr);
  EXPECT_TRUE(server->getConn().cryptoState->initialStream.writeBuffer.empty());
  EXPECT_TRUE(server->getConn()
                  .cryptoState->initialStream.retransmissionBuffer.empty());
}

TEST_F(QuicUnencryptedServerTransportTest, TestPendingZeroRttData) {
  auto data = IOBuf::copyBuffer("bad data");
  size_t expectedPendingLen =
      server->getConn().transportSettings.maxPacketsToBuffer;
  for (size_t i = 0; i < expectedPendingLen + 10; ++i) {
    StreamId streamId = static_cast<StreamId>(i);
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        server->getConn().serverConnectionId.value_or(getTestConnectionId(1)),
        clientNextAppDataPacketNum++,
        streamId,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */,
        std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
    EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));
    deliverData(std::move(packetData));
  }
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingZeroRttData->size(), expectedPendingLen);

  server->getNonConstConn().pendingZeroRttData->clear();
  deliverData(IOBuf::create(0));
  EXPECT_TRUE(server->getConn().pendingZeroRttData->empty());
}

TEST_F(QuicUnencryptedServerTransportTest, TestPendingOneRttData) {
  recvClientHello();
  auto data = IOBuf::copyBuffer("bad data");
  size_t expectedPendingLen =
      server->getConn().transportSettings.maxPacketsToBuffer;
  for (size_t i = 0; i < expectedPendingLen + 10; ++i) {
    StreamId streamId = static_cast<StreamId>(i);
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        streamId,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));
    deliverData(std::move(packetData));
  }
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), expectedPendingLen);

  server->getNonConstConn().pendingOneRttData->clear();
  deliverData(IOBuf::create(0));
  EXPECT_TRUE(server->getConn().pendingOneRttData->empty());
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestReceiveClientFinishedFromChangedPeerAddress) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  recvClientHello();

  folly::SocketAddress newPeer("100.101.102.103", 23456);

  try {
    recvClientFinished(true, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second,
      "Migration not allowed during handshake");
  EXPECT_TRUE(server->isClosed());

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketDrop, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketDropEvent*>(tmp.get());
  EXPECT_EQ(event->packetSize, 44);
  EXPECT_EQ(
      event->dropReason,
      QuicTransportStatsCallback::toString(
          PacketDropReason::PEER_ADDRESS_CHANGE));
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceiveHandshakePacketFromChangedPeerAddress) {
  server->getNonConstConn().transportSettings.disableMigration = false;

  recvClientHello();

  auto data = IOBuf::copyBuffer("bad data");
  folly::SocketAddress newPeer("100.101.102.103", 23456);

  try {
    recvClientFinished(true, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second,
      "Migration not allowed during handshake");
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    ReceiveZeroRttPacketFromChangedPeerAddress) {
  server->getNonConstConn().transportSettings.disableMigration = false;
  fakeHandshake->allowZeroRttKeys();

  recvClientHello();

  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(
          LongHeader::Types::ZeroRtt, server->getConn().supportedVersions[0]),
      false));
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  try {
    deliverData(std::move(packetData), true, &newPeer);
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second,
      "Migration not allowed during handshake");
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestNoCipherProcessPendingOneRttDataFromChangedAddress) {
  recvClientHello();

  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  folly::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), 1);

  try {
    recvClientFinished();
  } catch (const std::runtime_error& ex) {
    EXPECT_EQ(std::string(ex.what()), "Invalid migration");
  }
  EXPECT_TRUE(server->getConn().localConnectionError);
  EXPECT_EQ(
      server->getConn().localConnectionError->second, "Migration disabled");
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  EXPECT_EQ(server->getConn().pendingOneRttData, nullptr);
}

TEST_F(QuicUnencryptedServerTransportTest, TestWriteHandshakeAndZeroRtt) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  // This should trigger derivation of keys.
  recvClientHello();

  auto streamId = server->createBidirectionalStream().value();
  server->writeChain(streamId, IOBuf::copyBuffer("hello"), true, false);
  loopForWrites();
  auto clientCodec = makeClientEncryptedCodec(true);

  size_t numCryptoFrames = 0;
  size_t numNonCryptoFrames = 0;
  EXPECT_GT(serverWrites.size(), 1);
  AckStates ackStates;
  for (auto& write : serverWrites) {
    auto packetQueue = bufToQueue(write->clone());
    auto result = clientCodec->parsePacket(packetQueue, ackStates);
    auto& regularPacket = *result.regularPacket();
    ProtectionType protectionType = regularPacket.header.getProtectionType();
    bool handshakePacket = protectionType == ProtectionType::Initial ||
        protectionType == ProtectionType::Handshake;
    EXPECT_GE(regularPacket.frames.size(), 1);
    bool hasCryptoFrame = false;
    bool hasNonCryptoStream = false;
    for (auto& frame : regularPacket.frames) {
      hasCryptoFrame |= frame.asReadCryptoFrame() != nullptr;
      hasNonCryptoStream |= frame.asReadStreamFrame() != nullptr;
    }
    if (hasCryptoFrame) {
      EXPECT_TRUE(handshakePacket);
      numCryptoFrames++;
    }
    if (hasNonCryptoStream) {
      EXPECT_FALSE(handshakePacket);
      numNonCryptoFrames++;
    }
  }
  EXPECT_GE(numCryptoFrames, 1);
  EXPECT_GE(numNonCryptoFrames, 1);
}

TEST_F(QuicUnencryptedServerTransportTest, TestEncryptedDataBeforeCFIN) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  // This should trigger derivation of keys.
  recvClientHello();

  StreamId streamId = 4;
  recvEncryptedStream(streamId, *IOBuf::copyBuffer("hello"));

  auto stream = server->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_TRUE(stream->readBuffer.empty());
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    TestClearInFlightBytesLimitationAfterCFIN) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  server->getNonConstConn().transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  getFakeHandshakeLayer()->allowZeroRttKeys();
  auto originalUdpSize = server->getConn().udpSendPacketLen;

  setupClientReadCodec();

  recvClientHello();
  ASSERT_TRUE(server->getNonConstConn().writableBytesLimit.has_value());
  EXPECT_EQ(
      *server->getNonConstConn().writableBytesLimit,
      server->getConn().transportSettings.limitedCwndInMss * originalUdpSize);

  recvClientFinished();
  loopForWrites();
  EXPECT_EQ(server->getConn().writableBytesLimit, folly::none);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 4);
  std::array<::std::string, 4> updateArray = {kDerivedZeroRttReadCipher,
                                              kDerivedOneRttWriteCipher,
                                              kTransportReady,
                                              kDerivedOneRttReadCipher};
  for (int i = 0; i < 4; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, updateArray[i]);
  }
}

TEST_F(QuicUnencryptedServerTransportTest, TestSendHandshakeDone) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  setupClientReadCodec();
  recvClientHello(true, QuicVersion::QUIC_DRAFT);
  recvClientFinished(true, nullptr, QuicVersion::QUIC_DRAFT);
  auto& packets = server->getConn().outstandings.packets;
  ASSERT_FALSE(packets.empty());
  int numHandshakeDone = 0;
  for (auto& p : packets) {
    for (auto& f : p.packet.frames) {
      auto s = f.asQuicSimpleFrame();
      if (s) {
        if (s->asHandshakeDoneFrame()) {
          numHandshakeDone++;
        }
      }
    }
  }
  EXPECT_EQ(numHandshakeDone, 1);
}

TEST_F(
    QuicUnencryptedServerTransportTest,
    IncreaseLimitAfterReceivingNewPacket) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;
  getFakeHandshakeLayer()->allowZeroRttKeys();
  server->getNonConstConn().transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;

  auto originalUdpSize = server->getConn().udpSendPacketLen;
  setupClientReadCodec();

  recvClientHello();
  EXPECT_EQ(
      *server->getNonConstConn().writableBytesLimit,
      server->getConn().transportSettings.limitedCwndInMss * originalUdpSize);

  recvClientHello();

  // in tests the udp packet length changes
  auto expectedLen =
      server->getConn().transportSettings.limitedCwndInMss * originalUdpSize +
      server->getConn().transportSettings.limitedCwndInMss *
          server->getConn().udpSendPacketLen;
  EXPECT_NE(originalUdpSize, server->getConn().udpSendPacketLen);
  EXPECT_EQ(*server->getNonConstConn().writableBytesLimit, expectedLen);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 3);
  std::array<::std::string, 3> updateArray = {
      kDerivedZeroRttReadCipher, kDerivedOneRttWriteCipher, kTransportReady};
  for (int i = 0; i < 3; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
    EXPECT_EQ(event->update, updateArray[i]);
  }
}

TEST_F(QuicUnencryptedServerTransportTest, MaxReceivePacketSizeTooLarge) {
  getFakeHandshakeLayer()->allowZeroRttKeys();
  auto originalUdpSize = server->getConn().udpSendPacketLen;
  fakeHandshake->maxRecvPacketSize = 4096;
  setupClientReadCodec();
  recvClientHello();
  EXPECT_NE(originalUdpSize, server->getConn().udpSendPacketLen);
  EXPECT_EQ(server->getConn().udpSendPacketLen, kDefaultUDPSendPacketLen);
}

TEST_F(QuicUnencryptedServerTransportTest, TestGarbageData) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  server->getNonConstConn().qLogger = qLogger;

  auto data = IOBuf::copyBuffer("bad data");
  PacketNum nextPacket = clientNextInitialPacketNum++;
  auto aead = getInitialCipher();
  auto headerCipher = getInitialHeaderCipher();
  auto packet = createCryptoPacket(
      *clientConnectionId,
      *clientConnectionId,
      nextPacket,
      QuicVersion::QUIC_DRAFT,
      ProtectionType::Initial,
      *IOBuf::copyBuffer("CHLO"),
      *aead,
      0 /* largestAcked */);
  auto packetData =
      packetToBufCleartext(packet, *aead, *headerCipher, nextPacket);
  packetData->prependChain(IOBuf::copyBuffer("garbage in"));
  deliverData(std::move(packetData));
  EXPECT_NE(server->getConn().readCodec, nullptr);
  EXPECT_NE(server->getConn().initialWriteCipher, nullptr);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketBuffered, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketBufferedEvent*>(tmp.get());
  EXPECT_EQ(event->packetNum, nextPacket);
  EXPECT_EQ(event->protectionType, ProtectionType::KeyPhaseZero);
  EXPECT_EQ(event->packetSize, 10);
}

Buf getHandshakePacketWithFrame(
    QuicWriteFrame frame,
    ConnectionId connId,
    Aead& clientWriteCipher,
    PacketNumberCipher& headerCipher) {
  PacketNum clientPacketNum = folly::Random::rand32();
  LongHeader header(
      LongHeader::Types::Handshake,
      connId,
      connId,
      clientPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      std::move(header),
      clientPacketNum / 2 /* largestAcked */);
  builder.encodePacketHeader();
  builder.accountForCipherOverhead(clientWriteCipher.getCipherOverhead());
  writeFrame(std::move(frame), builder);
  return packetToBufCleartext(
      std::move(builder).buildPacket(),
      clientWriteCipher,
      headerCipher,
      clientPacketNum);
}

TEST_F(QuicUnencryptedServerTransportTest, TestNotAllowedInUnencryptedPacket) {
  // This should trigger derivation of keys.
  recvClientHello();

  StreamId streamId = 4;
  auto data = IOBuf::copyBuffer("data");

  EXPECT_THROW(
      deliverData(getHandshakePacketWithFrame(
          MaxStreamDataFrame(streamId, 100),
          *clientConnectionId,
          *getInitialCipher(),
          *getInitialHeaderCipher())),
      std::runtime_error);
  EXPECT_TRUE(server->error());
}

TEST_F(QuicUnencryptedServerTransportTest, TestCloseWhileAsyncPending) {
  folly::EventBase testLooper;
  setupClientReadCodec();
  getFakeHandshakeLayer()->initialize(&testLooper, server.get());

  recvClientHello();
  testLooper.loop();

  // Make sure the test looper worked.
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(getCryptoStreamData(), IOBuf::copyBuffer("SHLO")));

  recvClientFinished();

  server->close(std::make_pair(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("hello")));
  EXPECT_TRUE(server->isClosed());
  testLooper.loop();

  EXPECT_EQ(server->getConn().oneRttWriteCipher, nullptr);

  StreamId streamId = 4;
  auto data = IOBuf::copyBuffer("data");

  EXPECT_THROW(
      deliverData(getHandshakePacketWithFrame(
          MaxStreamDataFrame(streamId, 100),
          *clientConnectionId,
          *getInitialCipher(),
          *getInitialHeaderCipher())),
      std::runtime_error);
}

struct FizzHandshakeParam {
  FizzHandshakeParam(bool argCHLOSync, bool argCFINSync, bool argAcceptZeroRtt)
      : chloSync(argCHLOSync),
        cfinSync(argCFINSync),
        acceptZeroRtt(argAcceptZeroRtt) {}
  bool chloSync;
  bool cfinSync;
  bool acceptZeroRtt;
};

class QuicServerTransportPendingDataTest
    : public QuicUnencryptedServerTransportTest,
      public WithParamInterface<FizzHandshakeParam> {
 public:
  ~QuicServerTransportPendingDataTest() override {
    loopForWrites();
  }

  void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        GetParam().chloSync,
        GetParam().cfinSync);
    if (GetParam().acceptZeroRtt) {
      fakeHandshake->allowZeroRttKeys();
    }
  }
};

INSTANTIATE_TEST_CASE_P(
    QuicServerTransportPendingDataTests,
    QuicServerTransportPendingDataTest,
    Values(
        FizzHandshakeParam(false, false, false),
        FizzHandshakeParam(false, false, true),
        FizzHandshakeParam(false, true, false),
        FizzHandshakeParam(false, true, true),
        FizzHandshakeParam(true, false, false),
        FizzHandshakeParam(true, false, true),
        FizzHandshakeParam(true, true, false),
        FizzHandshakeParam(true, true, true)));

TEST_P(
    QuicServerTransportPendingDataTest,
    TestNoCipherProcessPendingZeroRttData) {
  server->getNonConstConn().qLogger =
      std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  recvClientHello(false);
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  // Write packet with zero rtt keys
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(
          LongHeader::Types::ZeroRtt, server->getConn().supportedVersions[0]),
      false));
  deliverData(std::move(packetData), false);
  if (GetParam().acceptZeroRtt) {
    if (!GetParam().chloSync) {
      EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
      EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
      loopForWrites();
    }
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
    EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  } else {
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
    EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
  }
  EXPECT_EQ(
      server->getConn().qLogger->scid, server->getConn().serverConnectionId);
}

TEST_P(
    QuicServerTransportPendingDataTest,
    TestNoCipherProcessPendingOneRttData) {
  server->getNonConstConn().qLogger =
      std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  recvClientHello();
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  // Write packet with zero rtt keys
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none,
      false));
  deliverData(std::move(packetData));
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), 1);

  recvClientFinished();
  EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
  EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  EXPECT_EQ(server->getConn().pendingOneRttData, nullptr);
  EXPECT_EQ(
      server->getConn().qLogger->scid, server->getConn().serverConnectionId);
}

TEST_P(
    QuicServerTransportPendingDataTest,
    TestNoCipherProcessingZeroAndOneRttData) {
  server->getNonConstConn().qLogger =
      std::make_shared<quic::FileQLogger>(VantagePoint::Server);
  recvClientHello(false);
  auto data = IOBuf::copyBuffer("bad data");
  StreamId streamId = 2;
  // Write packet with zero rtt keys
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(
          LongHeader::Types::ZeroRtt, server->getConn().supportedVersions[0]),
      false));
  deliverData(std::move(packetData), false);
  if (GetParam().acceptZeroRtt) {
    if (!GetParam().chloSync) {
      EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
      EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
      loopForWrites();
    }
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 1);
    EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  } else {
    EXPECT_EQ(server->getConn().streamManager->streamCount(), 0);
    EXPECT_EQ(server->getConn().pendingZeroRttData->size(), 1);
  }
  loopForWrites();

  StreamId streamId2 = 4;
  // Write packet with zero rtt keys
  auto packetData2 = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      streamId2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData2));
  EXPECT_EQ(
      server->getConn().streamManager->streamCount(),
      GetParam().acceptZeroRtt ? 1 : 0);
  EXPECT_EQ(server->getConn().pendingOneRttData->size(), 1);

  recvClientFinished();
  EXPECT_EQ(
      server->getConn().streamManager->streamCount(),
      GetParam().acceptZeroRtt ? 2 : 1);
  EXPECT_EQ(server->getConn().pendingZeroRttData, nullptr);
  EXPECT_EQ(server->getConn().pendingOneRttData, nullptr);
  EXPECT_EQ(
      server->getConn().qLogger->scid, server->getConn().serverConnectionId);
}

/**
 * Test handshake process with different parameters:
 * sync CHLO processing, sync CFIN processing, accept 0-rtt
 */
class QuicServerTransportHandshakeTest
    : public QuicUnencryptedServerTransportTest,
      public WithParamInterface<FizzHandshakeParam> {
 public:
  ~QuicServerTransportHandshakeTest() override {
    // We need an extra pump here for some reason.
    loopForWrites();
  }

  void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        GetParam().chloSync,
        GetParam().cfinSync);
    if (GetParam().acceptZeroRtt) {
      fakeHandshake->allowZeroRttKeys();
    }
  }

  void expectWriteNewSessionTicket() override {
    std::string appParams("APP params");
    server->setEarlyDataAppParamsFunctions(
        [](const folly::Optional<std::string>&, const Buf&) { return false; },
        [=]() -> Buf { return folly::IOBuf::copyBuffer(appParams); });
    EXPECT_CALL(*getFakeHandshakeLayer(), writeNewSessionTicket(_))
        .WillOnce(Invoke([=](const AppToken& appToken) {
          auto& params = appToken.transportParams.parameters;

          auto initialMaxData = *getIntegerParameter(
              TransportParameterId::initial_max_data, params);
          EXPECT_EQ(
              initialMaxData,
              server->getConn()
                  .transportSettings.advertisedInitialConnectionWindowSize);

          auto initialMaxStreamDataBidiLocal = *getIntegerParameter(
              TransportParameterId::initial_max_stream_data_bidi_local, params);
          auto initialMaxStreamDataBidiRemote = *getIntegerParameter(
              TransportParameterId::initial_max_stream_data_bidi_remote,
              params);
          auto initialMaxStreamDataUni = *getIntegerParameter(
              TransportParameterId::initial_max_stream_data_bidi_remote,
              params);
          EXPECT_EQ(
              initialMaxStreamDataBidiLocal,
              server->getConn()
                  .transportSettings
                  .advertisedInitialBidiLocalStreamWindowSize);
          EXPECT_EQ(
              initialMaxStreamDataBidiRemote,
              server->getConn()
                  .transportSettings
                  .advertisedInitialBidiRemoteStreamWindowSize);
          EXPECT_EQ(
              initialMaxStreamDataUni,
              server->getConn()
                  .transportSettings.advertisedInitialUniStreamWindowSize);

          auto initialMaxStreamsBidi = *getIntegerParameter(
              TransportParameterId::initial_max_streams_bidi, params);
          auto initialMaxStreamsUni = *getIntegerParameter(
              TransportParameterId::initial_max_streams_uni, params);
          EXPECT_EQ(
              initialMaxStreamsBidi,
              server->getConn()
                  .transportSettings.advertisedInitialMaxStreamsBidi);
          EXPECT_EQ(
              initialMaxStreamsUni,
              server->getConn()
                  .transportSettings.advertisedInitialMaxStreamsUni);

          auto maxRecvPacketSize = *getIntegerParameter(
              TransportParameterId::max_packet_size, params);
          EXPECT_EQ(
              maxRecvPacketSize,
              server->getConn().transportSettings.maxRecvPacketSize);

          EXPECT_THAT(
              appToken.sourceAddresses, ContainerEq(expectedSourceToken_));

          EXPECT_TRUE(folly::IOBufEqualTo()(
              appToken.appParams, folly::IOBuf::copyBuffer(appParams)));
        }));
  }

  void testSetupConnection() {
    // If 0-rtt is accepted, one rtt write cipher will be available after CHLO
    // is processed
    if (GetParam().acceptZeroRtt) {
      EXPECT_CALL(connCallback, onTransportReady());
    }
    recvClientHello();

    // If 0-rtt is disabled, one rtt write cipher will be available after CFIN
    // is processed
    if (!GetParam().acceptZeroRtt) {
      EXPECT_CALL(connCallback, onTransportReady());
    }
    // onConnectionIdBound is always invoked after CFIN is processed
    EXPECT_CALL(routingCallback, onConnectionIdBound(_));
    // NST is always written after CFIN is processed
    expectWriteNewSessionTicket();
    recvClientFinished();
  }

 protected:
  std::vector<folly::IPAddress> expectedSourceToken_;
};

INSTANTIATE_TEST_CASE_P(
    QuicServerTransportHandshakeTests,
    QuicServerTransportHandshakeTest,
    Values(
        FizzHandshakeParam(false, false, false),
        FizzHandshakeParam(false, false, true),
        FizzHandshakeParam(false, true, false),
        FizzHandshakeParam(false, true, true),
        FizzHandshakeParam(true, false, false),
        FizzHandshakeParam(true, false, true),
        FizzHandshakeParam(true, true, false),
        FizzHandshakeParam(true, true, true)));

TEST_P(
    QuicServerTransportHandshakeTest,
    TestConnectionSetupWithoutSourceTokenInPsk) {
  serverCtx->setSendNewSessionTicket(false);
  expectedSourceToken_ = {clientAddr.getIPAddress()};
  testSetupConnection();
}

TEST_P(
    QuicServerTransportHandshakeTest,
    TestConnectionSetupWithSourceTokenInPsk) {
  serverCtx->setSendNewSessionTicket(false);
  auto ipAddr = folly::IPAddress("1.2.3.4");
  getFakeHandshakeLayer()->setSourceTokens({ipAddr});
  if (GetParam().acceptZeroRtt) {
    expectedSourceToken_ = {ipAddr, clientAddr.getIPAddress()};
  } else {
    expectedSourceToken_ = {clientAddr.getIPAddress()};
  }
  testSetupConnection();
}

TEST_P(QuicServerTransportHandshakeTest, TestD6DStartInstrumentationCallback) {
  auto mockObserver = std::make_unique<MockInstrumentationObserver>();
  server->addInstrumentationObserver(mockObserver.get());
  // Set oneRttReader so that maybeStartD6DPriobing passes its check
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  codec->setOneRttReadCipher(createNoOpAead());
  server->getNonConstConn().readCodec = std::move(codec);
  // And the state too
  server->getNonConstConn().d6d.state = D6DMachineState::BASE;
  EXPECT_CALL(*mockObserver, pmtuProbingStarted(_)).Times(1);
  // CHLO should be enough to trigger probing
  recvClientHello();
  server->removeInstrumentationObserver(mockObserver.get());
}

TEST_F(QuicServerTransportTest, TestRegisterAndHandleTransportKnobParams) {
  int flag = 0;
  server->registerKnobParamHandler(
      199, [&](QuicServerConnectionState* /* server_conn */, uint64_t val) {
        EXPECT_EQ(val, 10);
        flag = 1;
      });
  server->registerKnobParamHandler(
      200,
      [&](QuicServerConnectionState* /* server_conn */, uint64_t /* val */) {
        flag = 2;
      });
  server->handleKnobParams({
      {199, 10},
      {201, 20},
  });

  EXPECT_EQ(flag, 1);

  // ovewrite will fail, the new handler won't be called
  server->registerKnobParamHandler(
      199, [&](QuicServerConnectionState* /* server_conn */, uint64_t val) {
        EXPECT_EQ(val, 30);
        flag = 3;
      });

  server->handleKnobParams({
      {199, 10},
      {201, 20},
  });
  EXPECT_EQ(flag, 1);
}

TEST_F(QuicServerTransportTest, TestRegisterPMTUZeroBlackholeDetection) {
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::ZERO_PMTU_BLACKHOLE_DETECTION),
        1}});
  EXPECT_TRUE(server->getConn().d6d.noBlackholeDetection);
}

class QuicServerTransportForciblySetUDUPayloadSizeTest
    : public QuicServerTransportTest {
 public:
  bool getCanIgnorePathMTU() override {
    return false;
  }
};

TEST_F(
    QuicServerTransportForciblySetUDUPayloadSizeTest,
    TestHandleTransportKnobParamForciblySetUDPPayloadSize) {
  EXPECT_LT(server->getConn().udpSendPacketLen, 1452);
  server->handleKnobParams(
      {{static_cast<uint64_t>(
            TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE),
        1}});
  EXPECT_EQ(server->getConn().udpSendPacketLen, 1452);
}

} // namespace test
} // namespace quic
