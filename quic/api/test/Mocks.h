/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>

#include <folly/io/async/EventBase.h>
#include <quic/QuicException.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicSocket.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/Timers.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/state/StateData.h>

namespace quic {

class MockFrameScheduler : public FrameScheduler {
 public:
  ~MockFrameScheduler() override = default;

  MockFrameScheduler() : FrameScheduler("mock") {}

  // override methods accepting rvalue ref since gmock doesn't support it
  SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builderIn,
      uint32_t writableBytes) override {
    return _scheduleFramesForPacket(&builderIn, writableBytes);
  }

  MOCK_METHOD(bool, hasData, (), (const));
  MOCK_METHOD2(
      _scheduleFramesForPacket,
      SchedulingResult(PacketBuilderInterface*, uint32_t));
};

class MockReadCallback : public QuicSocket::ReadCallback {
 public:
  ~MockReadCallback() override = default;
  MOCK_METHOD(void, readAvailable, (StreamId), (noexcept));
  MOCK_METHOD(void, readError, (StreamId,
              (std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>)),
              (noexcept));
};

class MockPeekCallback : public QuicSocket::PeekCallback {
 public:
  ~MockPeekCallback() override = default;
  MOCK_METHOD(void, onDataAvailable,
              (StreamId, const folly::Range<PeekIterator>&), (noexcept));
};

class MockWriteCallback : public QuicSocket::WriteCallback {
 public:
  ~MockWriteCallback() override = default;

  MOCK_METHOD(void, onStreamWriteReady, (StreamId, uint64_t), (noexcept));
  MOCK_METHOD(void, onConnectionWriteReady, (uint64_t), (noexcept));

  using Error = std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>;
  MOCK_METHOD(void, onStreamWriteError, (StreamId, Error), (noexcept));
  MOCK_METHOD(void, onConnectionWriteError, (Error), (noexcept));
};

class MockConnectionCallback : public QuicSocket::ConnectionCallback {
 public:
  ~MockConnectionCallback() override = default;

  MOCK_METHOD(void, onFlowControlUpdate, (StreamId), (noexcept));
  MOCK_METHOD(void, onNewBidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD(void, onNewUnidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD(void, onStopSending, (StreamId, ApplicationErrorCode), (noexcept));
  MOCK_METHOD(void, onConnectionEnd, (), (noexcept));
  MOCK_METHOD(void, onConnectionError, ((std::pair<QuicErrorCode, std::string>)), (noexcept));
  MOCK_METHOD(void, onReplaySafe, (), (noexcept));
  MOCK_METHOD(void, onTransportReady, (), (noexcept));
  MOCK_METHOD(void, onFirstPeerPacketProcessed, (), (noexcept));
  MOCK_METHOD(void, onBidirectionalStreamsAvailable, (uint64_t), (noexcept));
  MOCK_METHOD(void, onUnidirectionalStreamsAvailable, (uint64_t), (noexcept));
  MOCK_METHOD(void, onAppRateLimited, (), (noexcept));
};

class MockDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  ~MockDeliveryCallback() override = default;
  MOCK_METHOD(void, onDeliveryAck,
              (StreamId, uint64_t, std::chrono::microseconds), (noexcept));
  MOCK_METHOD2(onCanceled, void(StreamId, uint64_t));
};

class MockByteEventCallback : public QuicSocket::ByteEventCallback {
 public:
  ~MockByteEventCallback() override = default;
  MOCK_METHOD1(onByteEvent, void(QuicSocket::ByteEvent));
  MOCK_METHOD1(onByteEventCanceled, void(QuicSocket::ByteEvent));

  static auto getTxMatcher(StreamId id, uint64_t offset) {
    return AllOf(
        testing::Field(
            &QuicSocket::ByteEvent::type,
            testing::Eq(QuicSocket::ByteEvent::Type::TX)),
        testing::Field(&QuicSocket::ByteEvent::id, testing::Eq(id)),
        testing::Field(&QuicSocket::ByteEvent::offset, testing::Eq(offset)));
  }

  static auto getAckMatcher(StreamId id, uint64_t offset) {
    return AllOf(
        testing::Field(
            &QuicSocket::ByteEvent::type,
            testing::Eq(QuicSocket::ByteEvent::Type::ACK)),
        testing::Field(&QuicSocket::ByteEvent::id, testing::Eq(id)),
        testing::Field(&QuicSocket::ByteEvent::offset, testing::Eq(offset)));
  }
};

class MockDataExpiredCallback : public QuicSocket::DataExpiredCallback {
 public:
  ~MockDataExpiredCallback() override = default;
  MOCK_METHOD(void, onDataExpired, (StreamId, uint64_t), (noexcept));
};

class MockDataRejectedCallback : public QuicSocket::DataRejectedCallback {
 public:
  ~MockDataRejectedCallback() override = default;
  MOCK_METHOD(void, onDataRejected, (StreamId, uint64_t), (noexcept));
};

class MockQuicTransport : public QuicServerTransport {
 public:
  using Ptr = std::shared_ptr<MockQuicTransport>;

  class RoutingCallback : public QuicServerTransport::RoutingCallback {
   public:
    virtual ~RoutingCallback() = default;

    // Called when a connection id is available
    virtual void onConnectionIdAvailable(
        QuicServerTransport::Ptr transport,
        ConnectionId id) noexcept = 0;

    // Called when a connecton id is bound and ip address should not
    // be used any more for routing.
    virtual void onConnectionIdBound(
        QuicServerTransport::Ptr transport) noexcept = 0;

    // Called when the connection is finished and needs to be Unbound.
    virtual void onConnectionUnbound(
        QuicServerTransport*,
        const QuicServerTransport::SourceIdentity& address,
        const std::vector<ConnectionIdData>& connectionIdData) noexcept = 0;
  };

  MockQuicTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionCallback& cb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicServerTransport(evb, std::move(sock), cb, ctx) {}

  virtual ~MockQuicTransport() {
    customDestructor();
  }

  MOCK_METHOD0(customDestructor, void());

  MOCK_METHOD(folly::EventBase*, getEventBase, (), (const));

  MOCK_CONST_METHOD0(getPeerAddress, const folly::SocketAddress&());

  MOCK_CONST_METHOD0(getOriginalPeerAddress, const folly::SocketAddress&());

  MOCK_METHOD(void, setOriginalPeerAddress, (const folly::SocketAddress&), ());

  MOCK_METHOD(void, accept, (), ());

  MOCK_METHOD(void, setTransportSettings, (TransportSettings), ());

  MOCK_METHOD(void, setPacingTimer, (TimerHighRes::SharedPtr), (noexcept));

  void onNetworkData(
      const folly::SocketAddress& peer,
      NetworkData&& networkData) noexcept override {
    onNetworkData(peer, networkData);
  }

  MOCK_METHOD(void, onNetworkData,
              (const folly::SocketAddress&, const NetworkData&), (noexcept));

  MOCK_METHOD(void, setRoutingCallback,
              (QuicServerTransport::RoutingCallback*), (noexcept));

  MOCK_METHOD(void, setSupportedVersions,
              (const std::vector<QuicVersion>&), (noexcept));

  MOCK_METHOD(void, setServerConnectionIdParams, (ServerConnectionIdParams),
              (noexcept));

  using Error = folly::Optional<std::pair<QuicErrorCode, std::string>>;
  MOCK_METHOD(void, close, (Error), (noexcept));
  MOCK_METHOD(void, closeNow, (Error), (noexcept));

  MOCK_METHOD(bool, hasShutdown, (), (const));

  MOCK_METHOD(folly::Optional<ConnectionId>, getClientConnectionId, (),
              (const));

  MOCK_METHOD(folly::Optional<ConnectionId>, getClientChosenDestConnectionId,
              (), (const));

  MOCK_METHOD(void, setTransportStatsCallback, (QuicTransportStatsCallback*),
              (noexcept));

  MOCK_METHOD(void, setConnectionIdAlgo, (ConnectionIdAlgo*), (noexcept));

  MOCK_METHOD1(setBufAccessor, void(BufAccessor*));
};

class MockLoopDetectorCallback : public LoopDetectorCallback {
 public:
  ~MockLoopDetectorCallback() override = default;
  MOCK_METHOD4(
      onSuspiciousWriteLoops,
      void(uint64_t, WriteDataReason, NoWriteReason, const std::string&));
  MOCK_METHOD2(onSuspiciousReadLoops, void(uint64_t, NoReadReason));
};

class MockLifecycleObserver : public LifecycleObserver {
 public:
  MOCK_METHOD(void, observerAttach, (QuicSocket*), (noexcept));
  MOCK_METHOD(void, observerDetach, (QuicSocket*), (noexcept));
  MOCK_METHOD(void, destroy, (QuicSocket*), (noexcept));
  MOCK_METHOD(void, evbAttach, (QuicSocket*, folly::EventBase*), (noexcept));
  MOCK_METHOD(void, evbDetach, (QuicSocket*, folly::EventBase*), (noexcept));
  MOCK_METHOD(void, close, (QuicSocket*,
              (const folly::Optional<std::pair<QuicErrorCode, std::string>>&)),
              (noexcept));
};

class MockInstrumentationObserver : public InstrumentationObserver {
 public:
  MOCK_METHOD(void, observerDetach, (QuicSocket*), (noexcept));
  MOCK_METHOD(void, appRateLimited, (QuicSocket*), (noexcept));
  MOCK_METHOD(void, packetLossDetected, (QuicSocket*, const ObserverLossEvent&),
              (noexcept));
  MOCK_METHOD(void, rttSampleGenerated, (QuicSocket*, const PacketRTT&),
              (noexcept));
  MOCK_METHOD(void, pmtuProbingStarted, (QuicSocket*), (noexcept));
  MOCK_METHOD(void, pmtuBlackholeDetected,
              (QuicSocket*, const PMTUBlackholeEvent&), (noexcept));
  MOCK_METHOD(void, pmtuUpperBoundDetected,
              (QuicSocket*, const PMTUUpperBoundEvent&), (noexcept));

  static auto getLossPacketMatcher(bool reorderLoss, bool timeoutLoss) {
    return AllOf(
        testing::Field(
            &InstrumentationObserver::LostPacket::lostByReorderThreshold,
            testing::Eq(reorderLoss)),
        testing::Field(
            &InstrumentationObserver::LostPacket::lostByTimeout,
            testing::Eq(timeoutLoss)));
  }
};

inline std::ostream& operator<<(std::ostream& os, const MockQuicTransport&) {
  return os;
}
} // namespace quic
