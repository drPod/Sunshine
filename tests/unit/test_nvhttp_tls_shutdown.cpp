/**
 * @file tests/unit/test_nvhttp_tls_shutdown.cpp
 * @brief Verify TLS connection destruction cannot wait indefinitely for a pooled client.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <chrono>
#include <future>
#include <memory>
#include <thread>

// local includes
#include <src/crypto.h>
#include <src/nvhttp.h>
#include <src/utility.h>

/**
 * @brief Destroying a TLS connection must finish while its peer withholds close_notify.
 */
TEST(HttpsShutdownTest, PooledClientCannotBlockConnectionDestruction) {
  using namespace std::chrono_literals;
  using boost::asio::ip::tcp;

  const auto credentials = crypto::gen_creds("Sunshine TLS shutdown test", 2048);
  boost::asio::io_context server_io;
  boost::asio::io_context client_io;
  boost::asio::ssl::context server_context {boost::asio::ssl::context::tls_server};
  server_context.use_certificate_chain(boost::asio::buffer(credentials.x509));
  server_context.use_private_key(boost::asio::buffer(credentials.pkey), boost::asio::ssl::context::pem);
  boost::asio::ssl::context client_context {boost::asio::ssl::context::tls_client};
  client_context.set_verify_mode(boost::asio::ssl::verify_none);

  tcp::acceptor acceptor {server_io, {boost::asio::ip::address_v4::loopback(), 0}};
  auto connection = std::make_unique<nvhttp::SunshineHTTPS>(server_io, server_context);
  boost::asio::ssl::stream<tcp::socket> client {client_io, client_context};
  std::promise<bool> accepted;
  auto accepted_future = accepted.get_future();
  std::promise<void> destroyed;
  auto destroyed_future = destroyed.get_future();
  acceptor.async_accept(connection->lowest_layer(), [&](const auto &ec) {
    if (ec) {
      accepted.set_value(false);
      return;
    }
    connection->async_handshake(boost::asio::ssl::stream_base::server, [&](const auto &error) {
      accepted.set_value(!error);
    });
  });
  auto work = boost::asio::make_work_guard(server_io);
  std::jthread server_thread([&]() {
    server_io.run();
  });
  // Release an unfixed destructor before joining the worker, even on failure.
  auto cleanup = util::fail_guard([&]() {
    boost::system::error_code ec;
    client.lowest_layer().close(ec);
    work.reset();
    server_io.stop();
    server_thread.join();
  });

  client.lowest_layer().connect(acceptor.local_endpoint());
  bool connected = false;
  client.async_handshake(boost::asio::ssl::stream_base::client, [&](const auto &ec) {
    connected = !ec;
  });
  client_io.run_for(2s);
  ASSERT_TRUE(connected);
  ASSERT_EQ(accepted_future.wait_for(2s), std::future_status::ready);
  ASSERT_TRUE(accepted_future.get());

  boost::asio::post(server_io, [&]() {
    connection.reset();
    destroyed.set_value();
  });
  // Do not shut down or read from the peer: pooled clients leave it open.
  EXPECT_EQ(destroyed_future.wait_for(2s), std::future_status::ready);
}
