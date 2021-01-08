/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>

#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/state/ServerConnectionIdRejector.h>

namespace quic {

class MockServerConnectionIdRejector : public ServerConnectionIdRejector {
 public:
  MOCK_METHOD(bool, rejectConnectionIdNonConst,
              (const ConnectionId), (noexcept));

  bool rejectConnectionId(const ConnectionId& id) const noexcept override {
    return const_cast<MockServerConnectionIdRejector&>(*this)
        .rejectConnectionIdNonConst(id);
  }
};

class MockQuicServerTransportFactory : public QuicServerTransportFactory {
 public:
  ~MockQuicServerTransportFactory() override {}

  // wrapper for mocked make since gmock doesn't support methods with rvalue ref
  QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      const folly::SocketAddress& addr,
      std::shared_ptr<const fizz::server::FizzServerContext>
          ctx) noexcept override {
    return _make(evb, socket, addr, ctx);
  }

  MOCK_METHOD(QuicServerTransport::Ptr, _make, (folly::EventBase* evb,
              std::unique_ptr<folly::AsyncUDPSocket>& sock,
              const folly::SocketAddress&,
              std::shared_ptr<const fizz::server::FizzServerContext>),
              (noexcept));
};

class MockWorkerCallback : public QuicServerWorker::WorkerCallback {
 public:
  ~MockWorkerCallback() = default;
  MOCK_METHOD1(handleWorkerError, void(LocalErrorCode));

  MOCK_METHOD4(
      routeDataToWorkerLong,
      void(
          const folly::SocketAddress&,
          std::unique_ptr<RoutingData>&,
          std::unique_ptr<NetworkData>&,
          bool isForwardedData));

  MOCK_METHOD4(
      routeDataToWorkerShort,
      void(
          const folly::SocketAddress&,
          std::unique_ptr<RoutingData>&,
          std::unique_ptr<NetworkData>&,
          bool isForwardedData));

  void routeDataToWorker(
      const folly::SocketAddress& client,
      RoutingData&& routingDataIn,
      NetworkData&& networkDataIn,
      bool isForwardedData = false) {
    auto routingData = std::make_unique<RoutingData>(std::move(routingDataIn));
    auto networkData = std::make_unique<NetworkData>(std::move(networkDataIn));
    if (routingData->headerForm == HeaderForm::Long) {
      routeDataToWorkerLong(client, routingData, networkData, isForwardedData);
    } else {
      routeDataToWorkerShort(client, routingData, networkData, isForwardedData);
    }
  }
};

class MockQuicUDPSocketFactory : public QuicUDPSocketFactory {
 public:
  ~MockQuicUDPSocketFactory() = default;
  std::unique_ptr<folly::AsyncUDPSocket> make(folly::EventBase* evb, int fd) {
    return std::unique_ptr<folly::AsyncUDPSocket>(_make(evb, fd));
  }
  MOCK_METHOD2(_make, folly::AsyncUDPSocket*(folly::EventBase*, int));
};

class MockRoutingCallback : public QuicServerTransport::RoutingCallback {
 public:
  ~MockRoutingCallback() override = default;

  MOCK_METHOD(void, onConnectionIdAvailable,
              (QuicServerTransport::Ptr, ConnectionId), (noexcept));
  MOCK_METHOD(void, onConnectionIdBound, (QuicServerTransport::Ptr),
              (noexcept));
  MOCK_METHOD(void, onConnectionUnbound, (QuicServerTransport*,
              const QuicServerTransport::SourceIdentity&,
              const std::vector<ConnectionIdData>& connIdData), (noexcept));
};
} // namespace quic
