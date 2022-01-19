#include "common.h"
#include <bmq/hex.h>
extern "C" {
#include <sodium.h>
}


TEST_CASE("connections with curve authentication", "[curve][connect]") {
    std::string listen = random_localhost();
    BMQ server{
        "", "", // generate ephemeral keys
        false, // not a master node
        [](auto) { return ""; },
        get_logger("S» "),
        LogLevel::trace
    };

    server.listen_curve(listen);
    server.add_category("public", Access{AuthLevel::none});
    server.add_request_command("public", "hello", [&](Message& m) { m.send_reply("hi"); });
    server.start();

    BMQ client{get_logger("C» "), LogLevel::trace};

    client.start();

    auto pubkey = server.get_pubkey();
    std::atomic<bool> got{false};
    bool success = false;
    auto server_conn = client.connect_remote(address{listen, pubkey},
            [&](auto conn) { success = true; got = true; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("connection failed: " << reason); got = true; });

    wait_for_conn(got);
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE( success );
    }

    success = false;
    std::vector<std::string> parts;
    client.request(server_conn, "public.hello", [&](auto success_, auto parts_) { success = success_; parts = parts_; });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( success );
    }
}

TEST_CASE("self-connection MN optimization", "[connect][self]") {
    std::string pubkey, privkey;
    pubkey.resize(crypto_box_PUBLICKEYBYTES);
    privkey.resize(crypto_box_SECRETKEYBYTES);
    REQUIRE(sodium_init() != -1);
    auto listen_addr = random_localhost();
    crypto_box_keypair(reinterpret_cast<unsigned char*>(&pubkey[0]), reinterpret_cast<unsigned char*>(&privkey[0]));
    BMQ mn{
        pubkey, privkey,
        true,
        [&](auto pk) { if (pk == pubkey) return listen_addr; else return ""s; },
        get_logger("S» "),
        LogLevel::trace
    };

    mn.listen_curve(listen_addr, [&](auto ip, auto pk, auto mn) {
            auto lock = catch_lock();
            REQUIRE(ip == "127.0.0.1");
            REQUIRE(mn == (pk == pubkey));
            return AuthLevel::none;
    });
    mn.add_category("a", Access{AuthLevel::none});
    std::atomic<bool> invoked{false};
    mn.add_command("a", "b", [&](const Message& m) {
            invoked = true;
            auto lock = catch_lock();
            REQUIRE(m.conn.mn());
            REQUIRE(m.conn.pubkey() == pubkey);
            REQUIRE(!m.data.empty());
            REQUIRE(m.data[0] == "my data");
    });
    mn.set_active_mns({{pubkey}});

    mn.start();
    mn.send(pubkey, "a.b", "my data");
    wait_for_conn(invoked);
    {
        auto lock = catch_lock();
        REQUIRE(invoked);
    }
}

TEST_CASE("plain-text connections", "[plaintext][connect]") {
    std::string listen = random_localhost();
    BMQ server{get_logger("S» "), LogLevel::trace};

    server.add_category("public", Access{AuthLevel::none});
    server.add_request_command("public", "hello", [&](Message& m) { m.send_reply("hi"); });

    server.listen_plain(listen);

    server.start();

    BMQ client{get_logger("C» "), LogLevel::trace};

    client.start();

    std::atomic<bool> got{false};
    bool success = false;
    auto c = client.connect_remote(address{listen},
            [&](auto conn) { success = true; got = true; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("connection failed: " << reason); got = true; }
            );

    wait_for_conn(got);
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE( success );
    }

    success = false;
    std::vector<std::string> parts;
    client.request(c, "public.hello", [&](auto success_, auto parts_) { success = success_; parts = parts_; });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( success );
    }
}

TEST_CASE("post-start listening", "[connect][listen]") {
    BMQ server{get_logger("S» "), LogLevel::trace};
    server.add_category("x", AuthLevel::none)
        .add_request_command("y", [&](Message& m) { m.send_reply("hi", m.data[0]); });
    server.start();
    std::atomic<int> listens = 0;
    auto listen_curve = random_localhost();
    server.listen_curve(listen_curve, nullptr, [&](bool success) { if (success) listens++; });
    auto listen_plain = random_localhost();
    server.listen_plain(listen_plain, nullptr, [&](bool success) { if (success) listens += 10; });

    wait_for([&] { return listens.load() >= 11; });
    {
        auto lock = catch_lock();
        REQUIRE( listens == 11 );
    }

    // This should fail since we're already listening on it:
    server.listen_curve(listen_plain, nullptr, [&](bool success) { if (!success) listens++; });

    wait_for([&] { return listens.load() >= 12; });
    {
        auto lock = catch_lock();
        REQUIRE( listens == 12 );
    }


    BMQ client{get_logger("C1» "), LogLevel::trace};
    client.start();
    std::atomic<int> conns = 0;
    auto c1 = client.connect_remote(address{listen_curve, server.get_pubkey()},
            [&](auto) { conns++; },
            [&](auto, auto why) { auto lock = catch_lock(); UNSCOPED_INFO("connection failed: " << why); });
    auto c2 = client.connect_remote(address{listen_plain},
            [&](auto) { conns += 10; },
            [&](auto, auto why) { auto lock = catch_lock(); UNSCOPED_INFO("connection failed: " << why); });


    wait_for([&] { return conns.load() >= 11; });
    {
        auto lock = catch_lock();
        REQUIRE( conns == 11 );
    }

    std::atomic<int> replies = 0;
    std::string reply1, reply2;
    client.request(c1, "x.y", [&](auto success, auto parts) { replies++; for (auto& p : parts) reply1 += p; }, " world");
    client.request(c2, "x.y", [&](auto success, auto parts) { replies += 10; for (auto& p : parts) reply2 += p; }, " cat");

    wait_for([&] { return replies.load() >= 11; });
    {
        auto lock = catch_lock();
        REQUIRE( replies == 11 );
        REQUIRE( reply1 == "hi world" );
        REQUIRE( reply2 == "hi cat" );
    }
}

TEST_CASE("unique connection IDs", "[connect][id]") {
    std::string listen = random_localhost();
    BMQ server{get_logger("S» "), LogLevel::trace};

    ConnectionID first, second;
    server.add_category("x", Access{AuthLevel::none})
        .add_request_command("x", [&](Message& m) { first = m.conn; m.send_reply("hi"); })
        .add_request_command("y", [&](Message& m) { second = m.conn; m.send_reply("hi"); })
        ;

    server.listen_plain(listen);

    server.start();

    BMQ client1{get_logger("C1» "), LogLevel::trace};
    BMQ client2{get_logger("C2» "), LogLevel::trace};
    client1.start();
    client2.start();

    std::atomic<bool> good1{false}, good2{false};
    auto r1 = client1.connect_remote(address{listen},
            [&](auto conn) { good1 = true; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("connection failed: " << reason); }
            );
    auto r2 = client2.connect_remote(address{listen},
            [&](auto conn) { good2 = true; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("connection failed: " << reason); }
            );

    wait_for_conn(good1);
    wait_for_conn(good2);
    {
        auto lock = catch_lock();
        REQUIRE( good1 );
        REQUIRE( good2 );
        REQUIRE( first == second );
        REQUIRE_FALSE( first );
        REQUIRE_FALSE( second );
    }

    good1 = false;
    good2 = false;
    client1.request(r1, "x.x", [&](auto success_, auto parts_) { good1 = true; });
    client2.request(r2, "x.y", [&](auto success_, auto parts_) { good2 = true; });
    reply_sleep();

    {
        auto lock = catch_lock();
        REQUIRE( good1 );
        REQUIRE( good2 );
        REQUIRE_FALSE( first == second );
        REQUIRE_FALSE( std::hash<ConnectionID>{}(first) == std::hash<ConnectionID>{}(second) );
    }
}


TEST_CASE("MN disconnections", "[connect][disconnect]") {
    std::vector<std::unique_ptr<BMQ>> bmq;
    std::vector<std::string> pubkey, privkey;
    std::unordered_map<std::string, std::string> conn;
    REQUIRE(sodium_init() != -1);
    for (int i = 0; i < 3; i++) {
        pubkey.emplace_back();
        privkey.emplace_back();
        pubkey[i].resize(crypto_box_PUBLICKEYBYTES);
        privkey[i].resize(crypto_box_SECRETKEYBYTES);
        crypto_box_keypair(reinterpret_cast<unsigned char*>(&pubkey[i][0]), reinterpret_cast<unsigned char*>(&privkey[i][0]));
        conn.emplace(pubkey[i], random_localhost());
    }
    std::atomic<int> his{0};
    for (int i = 0; i < pubkey.size(); i++) {
        bmq.push_back(std::make_unique<BMQ>(
            pubkey[i], privkey[i], true,
            [conn](auto pk) { auto it = conn.find((std::string) pk); if (it != conn.end()) return it->second; return ""s; },
            get_logger("S" + std::to_string(i) + "» "),
            LogLevel::trace
        ));
        auto& server = *bmq.back();

        server.listen_curve(conn[pubkey[i]]);
        server.add_category("mn", Access{AuthLevel::none, true})
            .add_command("hi", [&](Message& m) { his++; });
        server.set_active_mns({pubkey.begin(), pubkey.end()});
        server.start();
    }

    bmq[0]->send(pubkey[1], "mn.hi");
    bmq[0]->send(pubkey[2], "mn.hi");
    bmq[2]->send(pubkey[0], "mn.hi");
    bmq[2]->send(pubkey[1], "mn.hi");
    bmq[1]->send(pubkey[0], "BYE");
    bmq[0]->send(pubkey[2], "mn.hi");
    std::this_thread::sleep_for(50ms * TIME_DILATION);

    auto lock = catch_lock();
    REQUIRE(his == 5);
}

TEST_CASE("MN auth checks", "[sandwich][auth]") {
    // When a remote connects, we check its authentication level; if at the time of connection it
    // isn't recognized as a MN but tries to invoke a MN command it'll be told to disconnect; if it
    // tries to send again it should reconnect and reauthenticate.  This test is meant to test this
    // pattern where the reconnection/reauthentication now authenticates it as a MN.
    std::string listen = random_localhost();
    std::string pubkey, privkey;
    pubkey.resize(crypto_box_PUBLICKEYBYTES);
    privkey.resize(crypto_box_SECRETKEYBYTES);
    REQUIRE(sodium_init() != -1);
    crypto_box_keypair(reinterpret_cast<unsigned char*>(&pubkey[0]), reinterpret_cast<unsigned char*>(&privkey[0]));
    BMQ server{
        pubkey, privkey,
        true, // master node
        [](auto) { return ""; },
        get_logger("A» "),
        LogLevel::trace
    };

    std::atomic<bool> incoming_is_mn{false};
    server.listen_curve(listen);
    server.add_category("public", Access{AuthLevel::none})
        .add_request_command("hello", [&](Message& m) { m.send_reply("hi"); })
        .add_request_command("sudo", [&](Message& m) {
                server.update_active_mns({{m.conn.pubkey()}}, {});
                m.send_reply("making sandwiches");
        })
        .add_request_command("nosudo", [&](Message& m) {
                // Send the reply *first* because if we do it the other way we'll have just removed
                // ourselves from the list of MNs and thus would try to open an outbound connection
                // to deliver it since it's still queued as a message to a MN.
                m.send_reply("make them yourself");
                server.update_active_mns({}, {{m.conn.pubkey()}});
        });
    server.add_category("sandwich", Access{AuthLevel::none, true})
        .add_request_command("make", [&](Message& m) { m.send_reply("okay"); });
    server.start();

    BMQ client{
        "", "", false,
        [&](auto remote_pk) { if (remote_pk == pubkey) return listen; return ""s; },
        get_logger("B» "), LogLevel::trace};
    client.start();

    std::atomic<bool> got{false};
    bool success;
    client.request(pubkey, "public.hello", [&](auto success_, auto) { success = success_; got = true; });
    wait_for_conn(got);
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE( success );
    }

    got = false;
    using dvec = std::vector<std::string>;
    dvec data;
    client.request(pubkey, "sandwich.make", [&](auto success_, auto data_) {
            success = success_;
            data = std::move(data_);
            got = true;
    });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE_FALSE( success );
        REQUIRE( data == dvec{{"FORBIDDEN_MN"}} );
    }

    // Somebody set up us the bomb.  Main sudo turn on.
    got = false;
    client.request(pubkey, "public.sudo", [&](auto success_, auto data_) { success = success_; data = data_; got = true; });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE( success );
        REQUIRE( data == dvec{{"making sandwiches"}} );
    }

    got = false;
    client.request(pubkey, "sandwich.make", [&](auto success_, auto data_) {
            success = success_;
            data = std::move(data_);
            got = true;
    });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE( success );
        REQUIRE( data == dvec{{"okay"}} );
    }

    // Take off every 'SUDO', You [not] know what you doing
    got = false;
    client.request(pubkey, "public.nosudo", [&](auto success_, auto data_) { success = success_; data = data_; got = true; });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE( success );
        REQUIRE( data == dvec{{"make them yourself"}} );
    }

    got = false;
    client.request(pubkey, "sandwich.make", [&](auto success_, auto data_) {
            success = success_;
            data = std::move(data_);
            got = true;
    });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( got );
        REQUIRE_FALSE( success );
        REQUIRE( data == dvec{{"FORBIDDEN_MN"}} );
    }
}

TEST_CASE("MN single worker test", "[connect][worker]") {
    // Tests a failure case that could trigger when all workers are allocated (here we make that
    // simpler by just having one worker).
    std::string listen = random_localhost();
    BMQ server{
        "", "",
        false, // master node
        [](auto) { return ""; },
        get_logger("S» "),
        LogLevel::trace
    };
    server.set_general_threads(1);
    server.set_batch_threads(0);
    server.set_reply_threads(0);
    server.listen_plain(listen);
    server.add_category("c", Access{AuthLevel::none})
        .add_request_command("x", [&](Message& m) { m.send_reply(); })
        ;
    server.start();

    BMQ client{get_logger("B» "), LogLevel::trace};
    client.start();
    auto conn = client.connect_remote(address{listen}, [](auto) {}, [](auto, auto) {});

    std::atomic<int> got{0};
    std::atomic<int> success{0};
    client.request(conn, "c.x", [&](auto success_, auto) { if (success_) ++success; ++got; });
    wait_for([&] { return got.load() >= 1; });
    {
        auto lock = catch_lock();
        REQUIRE( success == 1 );
    }
    client.request(conn, "c.x", [&](auto success_, auto) { if (success_) ++success; ++got; });
    wait_for([&] { return got.load() >= 2; });
    {
        auto lock = catch_lock();
        REQUIRE( success == 2 );
    }

}

TEST_CASE("MN backchatter", "[connect][mn]") {
    // When we have a MN connection A -> B and then B sends a message to A on that existing
    // connection, A should see it as coming from B.
    std::vector<std::unique_ptr<BMQ>> bmq;
    std::vector<std::string> pubkey, privkey;
    std::unordered_map<std::string, std::string> conn;
    REQUIRE(sodium_init() != -1);
    for (int i = 0; i < 2; i++) {
        pubkey.emplace_back();
        privkey.emplace_back();
        pubkey[i].resize(crypto_box_PUBLICKEYBYTES);
        privkey[i].resize(crypto_box_SECRETKEYBYTES);
        crypto_box_keypair(reinterpret_cast<unsigned char*>(&pubkey[i][0]), reinterpret_cast<unsigned char*>(&privkey[i][0]));
        conn.emplace(pubkey[i], random_localhost());
    }

    for (int i = 0; i < pubkey.size(); i++) {
        bmq.push_back(std::make_unique<BMQ>(
            pubkey[i], privkey[i], true,
            [conn](auto pk) { auto it = conn.find((std::string) pk); if (it != conn.end()) return it->second; return ""s; },
            get_logger("S" + std::to_string(i) + "» "),
            LogLevel::trace
        ));
        auto& server = *bmq.back();

        server.listen_curve(conn[pubkey[i]]);
        server.set_active_mns({pubkey.begin(), pubkey.end()});
    }
    std::string f;
    bmq[0]->add_category("a", Access{AuthLevel::none, true})
        .add_command("a", [&](Message& m) {
            m.bmq.send(m.conn, "b.b", "abc");
            //m.send_back("b.b", "abc");
        })
        .add_command("z", [&](Message& m) {
            auto lock = catch_lock();
            f = m.data[0];
        });
    bmq[1]->add_category("b", Access{AuthLevel::none, true})
        .add_command("b", [&](Message& m) {
            {
                auto lock = catch_lock();
                UNSCOPED_INFO("b.b from conn " << m.conn);
            }
            m.send_back("a.z", m.data[0]);
        });

    for (auto& server : bmq)
        server->start();

    auto c = bmq[1]->connect_mn(pubkey[0]);
    bmq[1]->send(c, "a.a");
    std::this_thread::sleep_for(50ms);

    auto lock = catch_lock();
    REQUIRE(f == "abc");
}

TEST_CASE("inproc connections", "[connect][inproc]") {
    std::string inproc_name = "foo";
    BMQ bmq{get_logger("bmq» "), LogLevel::trace};

    bmq.add_category("public", Access{AuthLevel::none});
    bmq.add_request_command("public", "hello", [&](Message& m) { m.send_reply("hi"); });

    bmq.start();

    std::atomic<int> got{0};
    bool success = false;
    auto c_inproc = bmq.connect_inproc(
            [&](auto conn) { success = true; got++; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("inproc connection failed: " << reason); got++; }
            );

    wait_for([&got] { return got.load() > 0; });
    {
        auto lock = catch_lock();
        REQUIRE( success );
        REQUIRE( got == 1 );
    }

    got = 0;
    success = false;
    bmq.request(c_inproc, "public.hello", [&](auto success_, auto parts_) {
        success = success_ && parts_.size() == 1 && parts_.front() == "hi"; got++;
    });
    reply_sleep();
    {
        auto lock = catch_lock();
        REQUIRE( got == 1 );
        REQUIRE( success );
    }
}

TEST_CASE("no explicit inproc listening", "[connect][inproc]") {
    BMQ bmq{get_logger("BMQ» "), LogLevel::trace};
    REQUIRE_THROWS_AS(bmq.listen_plain("inproc://foo"), std::logic_error);
    REQUIRE_THROWS_AS(bmq.listen_curve("inproc://foo"), std::logic_error);
}

TEST_CASE("inproc connection permissions", "[connect][inproc]") {
    std::string listen = random_localhost();
    BMQ bmq{get_logger("BMQ» "), LogLevel::trace};

    bmq.add_category("public", Access{AuthLevel::none});
    bmq.add_request_command("public", "hello", [&](Message& m) { m.send_reply("hi"); });
    bmq.add_category("private", Access{AuthLevel::admin});
    bmq.add_request_command("private", "handshake", [&](Message& m) { m.send_reply("yo dude"); });

    bmq.listen_plain(listen);

    bmq.start();

    std::atomic<int> got{0};
    bool success = false;
    auto c_inproc = bmq.connect_inproc(
            [&](auto conn) { success = true; got++; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("inproc connection failed: " << reason); got++; }
            );

    bool pub_success = false;
    auto c_pub = bmq.connect_remote(address{listen},
            [&](auto conn) { pub_success = true; got++; },
            [&](auto conn, std::string_view reason) { auto lock = catch_lock(); INFO("tcp connection failed: " << reason); got++; }
            );

    wait_for([&got] { return got.load() == 2; });
    {
        auto lock = catch_lock();
        REQUIRE( got == 2 );
        REQUIRE( success );
        REQUIRE( pub_success );
    }

    got = 0;
    success = false;
    pub_success = false;
    bool success_private = false;
    bool pub_success_private = false;
    bmq.request(c_inproc, "public.hello", [&](auto success_, auto parts_) {
        success = success_ && parts_.size() == 1 && parts_.front() == "hi"; got++;
    });
    bmq.request(c_pub, "public.hello", [&](auto success_, auto parts_) {
        pub_success = success_ && parts_.size() == 1 && parts_.front() == "hi"; got++;
    });
    bmq.request(c_inproc, "private.handshake", [&](auto success_, auto parts_) {
        success_private = success_ && parts_.size() == 1 && parts_.front() == "yo dude"; got++;
    });
    bmq.request(c_pub, "private.handshake", [&](auto success_, auto parts_) {
        pub_success_private = success_; got++;
    });
    wait_for([&got] { return got.load() == 4; });
    {
        auto lock = catch_lock();
        REQUIRE( got == 4 );
        REQUIRE( success );
        REQUIRE( pub_success );
        REQUIRE( success_private );
        REQUIRE_FALSE( pub_success_private );
    }
}
