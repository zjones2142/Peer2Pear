// test_group_protocol.cpp — tests for GroupProtocol.
//
// GroupProtocol owns:
//   1. Outbound send methods (text / leave / rename / avatar / member_update)
//      that fan out through a SendSealedFn callback per member.
//   2. The roster authorization gate isAuthorizedSender — the H2 audit
//      fix — with deny-by-default for unknown groups and bootstrap-on-
//      first-trusted-message semantics via upsertMembersFromTrustedMessage.
//   3. Per-group outbound seq counters + per-(group, sender) inbound
//      monotonic guard via recordInboundSeq.
//
// None of this requires a live session.  We give the protocol a mock
// SendSealedFn that captures every fan-out call, then assert the payload
// shape, recipient list, seq numbering, and roster state.

#include "GroupProtocol.hpp"

#include "CryptoEngine.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

using p2p_test::makeTempDir;

struct CapturedSend {
    std::string    peerId;
    nlohmann::json payload;
};

}  // namespace

class GroupProtocolSuite : public ::testing::Test {
protected:
    // Three identities (me, alice, bob) shared across every test case.
    static std::string                   s_meDir;
    static std::string                   s_aliceDir;
    static std::string                   s_bobDir;
    static std::unique_ptr<CryptoEngine> s_meCrypto;
    static std::unique_ptr<CryptoEngine> s_aliceCrypto;
    static std::unique_ptr<CryptoEngine> s_bobCrypto;
    static std::string                   s_meId;
    static std::string                   s_aliceId;
    static std::string                   s_bobId;

    static void SetUpTestSuite() {
        ASSERT_GE(sodium_init(), 0);

        s_meDir    = makeTempDir("p2p-gp-me-id");
        s_aliceDir = makeTempDir("p2p-gp-alice-id");
        s_bobDir   = makeTempDir("p2p-gp-bob-id");

        s_meCrypto = std::make_unique<CryptoEngine>();
        s_meCrypto->setDataDir(s_meDir);
        s_meCrypto->setPassphrase("gp-test-me");
        ASSERT_NO_THROW(s_meCrypto->ensureIdentity());

        s_aliceCrypto = std::make_unique<CryptoEngine>();
        s_aliceCrypto->setDataDir(s_aliceDir);
        s_aliceCrypto->setPassphrase("gp-test-alice");
        ASSERT_NO_THROW(s_aliceCrypto->ensureIdentity());

        s_bobCrypto = std::make_unique<CryptoEngine>();
        s_bobCrypto->setDataDir(s_bobDir);
        s_bobCrypto->setPassphrase("gp-test-bob");
        ASSERT_NO_THROW(s_bobCrypto->ensureIdentity());

        s_meId    = CryptoEngine::toBase64Url(s_meCrypto->identityPub());
        s_aliceId = CryptoEngine::toBase64Url(s_aliceCrypto->identityPub());
        s_bobId   = CryptoEngine::toBase64Url(s_bobCrypto->identityPub());
    }

    static void TearDownTestSuite() {
        s_meCrypto.reset();
        s_aliceCrypto.reset();
        s_bobCrypto.reset();
        std::error_code ec;
        std::filesystem::remove_all(s_meDir,    ec);
        std::filesystem::remove_all(s_aliceDir, ec);
        std::filesystem::remove_all(s_bobDir,   ec);
    }

    void SetUp() override {
        m_gp = std::make_unique<GroupProtocol>(*s_meCrypto);
        m_captured.clear();
        m_gp->setSendSealedFn(
            [this](const std::string& peer, const nlohmann::json& payload) {
                m_captured.push_back({peer, payload});
            });
    }

    // Count fan-outs that targeted a specific peer.
    int countTo(const std::string& peerId) const {
        return int(std::count_if(m_captured.begin(), m_captured.end(),
            [&](const CapturedSend& c) { return c.peerId == peerId; }));
    }

    std::unique_ptr<GroupProtocol> m_gp;
    std::vector<CapturedSend>      m_captured;
};

std::string                   GroupProtocolSuite::s_meDir;
std::string                   GroupProtocolSuite::s_aliceDir;
std::string                   GroupProtocolSuite::s_bobDir;
std::unique_ptr<CryptoEngine> GroupProtocolSuite::s_meCrypto;
std::unique_ptr<CryptoEngine> GroupProtocolSuite::s_aliceCrypto;
std::unique_ptr<CryptoEngine> GroupProtocolSuite::s_bobCrypto;
std::string                   GroupProtocolSuite::s_meId;
std::string                   GroupProtocolSuite::s_aliceId;
std::string                   GroupProtocolSuite::s_bobId;

// ── 1. Roster authorization (H2 gate) ────────────────────────────────────────

TEST_F(GroupProtocolSuite, IsAuthorizedSender_DenyByDefaultForUnknownGroup) {
    EXPECT_FALSE(m_gp->isAuthorizedSender("unknown-gid", s_aliceId));
}

TEST_F(GroupProtocolSuite, IsAuthorizedSender_EmptyInputsAreDenied) {
    EXPECT_FALSE(m_gp->isAuthorizedSender("",    s_aliceId));
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid", ""));
    EXPECT_FALSE(m_gp->isAuthorizedSender("",    ""));
}

TEST_F(GroupProtocolSuite, SetKnownMembers_AdmitsRosterPeers) {
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId, s_bobId});
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid", s_aliceId));
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid", s_bobId));
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid", "outsider"));
}

// ── 2. Bootstrap via first trusted message ───────────────────────────────────

TEST_F(GroupProtocolSuite, Upsert_BootstrapsWhenSenderIsInDeclaredList) {
    // First trusted group_msg for a new gid, sender IS in the member list.
    m_gp->upsertMembersFromTrustedMessage(
        "gid-new", s_aliceId, {s_meId, s_aliceId, s_bobId});
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid-new", s_aliceId));
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid-new", s_bobId));
}

TEST_F(GroupProtocolSuite, Upsert_RejectsBootstrapWhenSenderOmitsSelf) {
    // Attacker tries to seed a bogus roster that excludes themselves — this
    // is the H5 known-limitation first-mover race; we defend by only
    // accepting a list that the claimed sender is actually in.
    m_gp->upsertMembersFromTrustedMessage(
        "gid-x", s_aliceId, {s_meId, s_bobId});
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid-x", s_aliceId));
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid-x", s_bobId));
}

TEST_F(GroupProtocolSuite, Upsert_OnKnownGroupJustAddsSenderNoReplace) {
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId});
    // Subsequent trusted message includes a NEW peer claiming membership
    // and also lists an outsider.  For known groups we only auto-add the
    // sender — NOT every id in the payload — to prevent a member from
    // silently growing the roster.
    m_gp->upsertMembersFromTrustedMessage(
        "gid", s_bobId, {s_bobId, "outsider"});
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid", s_aliceId));
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid", s_bobId));
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid", "outsider"));
}

TEST_F(GroupProtocolSuite, RemoveMember_DropsFromRoster) {
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId, s_bobId});
    m_gp->removeMember("gid", s_aliceId);
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid", s_aliceId));
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid", s_bobId));
}

TEST_F(GroupProtocolSuite, ReplaceMembers_OverwritesExistingRoster) {
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId});
    m_gp->replaceMembers("gid", {s_meId, s_bobId});
    EXPECT_FALSE(m_gp->isAuthorizedSender("gid", s_aliceId));
    EXPECT_TRUE(m_gp->isAuthorizedSender("gid", s_bobId));
}

// ── 3. Inbound seq counter monotonicity ──────────────────────────────────────
//
// This class of bug was caught + reverted during the ChatController
// refactor: a recordInboundSeq that always overwrites would let an
// attacker lower the high-water mark with a replay and then sneak the
// next legit seq through the gate.  These tests pin the fix.

TEST_F(GroupProtocolSuite, RecordInboundSeq_FirstSeqReturnsNegativeOne) {
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 5), -1);
}

TEST_F(GroupProtocolSuite, RecordInboundSeq_AdvancesOnStrictlyGreater) {
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 1),  -1);
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 2),   1);
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 10),  2);
}

TEST_F(GroupProtocolSuite, RecordInboundSeq_ReplayDoesNotLowerHighWaterMark) {
    ASSERT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 10), -1);

    // Replays must return the prior high-water (caller drops them) AND
    // leave the stored seq at 10 — otherwise a follow-up "seq=10 again"
    // replay would pass the gate.
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 5), 10);
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 9), 10);

    // Confirm the counter didn't regress: another seq=10 still reports 10.
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 10), 10);

    // And the next legitimate seq=11 advances from 10, not from 9/5.
    EXPECT_EQ(m_gp->recordInboundSeq("gid", s_aliceId, 11), 10);
}

TEST_F(GroupProtocolSuite, RecordInboundSeq_PerGroupPerSenderIsolation) {
    // Different (group, sender) pairs track independently.
    ASSERT_EQ(m_gp->recordInboundSeq("gidA", s_aliceId, 100), -1);
    EXPECT_EQ(m_gp->recordInboundSeq("gidA", s_bobId,     5), -1);
    EXPECT_EQ(m_gp->recordInboundSeq("gidB", s_aliceId,   3), -1);
    // Advancing one doesn't affect the others.
    EXPECT_EQ(m_gp->recordInboundSeq("gidA", s_aliceId, 101), 100);
    EXPECT_EQ(m_gp->recordInboundSeq("gidA", s_bobId,     6),   5);
}

TEST_F(GroupProtocolSuite, SetSeqCounters_RestoresPersistedState) {
    std::map<std::string, int64_t> out{{"gid1", 7}, {"gid2", 3}};
    std::map<std::string, int64_t> in {{"gid1:" + s_aliceId, 42}};
    m_gp->setSeqCounters(out, in);
    EXPECT_EQ(m_gp->seqOut().at("gid1"), 7);
    EXPECT_EQ(m_gp->seqIn().at("gid1:" + s_aliceId), 42);

    // Next inbound for that sender must treat 42 as the existing high-water.
    EXPECT_EQ(m_gp->recordInboundSeq("gid1", s_aliceId, 43), 42);
    EXPECT_EQ(m_gp->recordInboundSeq("gid1", s_aliceId, 10), 43);
}

// ── 4. Outbound send methods ─────────────────────────────────────────────────

TEST_F(GroupProtocolSuite, SendText_FanoutExcludesSelfIncrementsSeq) {
    m_gp->sendText("gid", "My Group",
                   {s_meId, s_aliceId, s_bobId},
                   "hello all");

    // Two fan-outs: alice + bob.  Self is filtered.
    ASSERT_EQ(m_captured.size(), 2U);
    EXPECT_EQ(countTo(s_aliceId), 1);
    EXPECT_EQ(countTo(s_bobId),   1);
    EXPECT_EQ(countTo(s_meId),    0);

    // Every payload must share ts / msgId / seq since they're one logical
    // message — any divergence would double-count at the receiver.
    const auto& first = m_captured[0].payload;
    EXPECT_EQ(first["type"],      "group_msg");
    EXPECT_EQ(first["groupId"],   "gid");
    EXPECT_EQ(first["groupName"], "My Group");
    EXPECT_EQ(first["from"],      s_meId);
    EXPECT_EQ(first["text"],      "hello all");
    EXPECT_EQ(first["seq"].get<int64_t>(), 1);

    for (const auto& sent : m_captured) {
        EXPECT_EQ(sent.payload["msgId"], first["msgId"]);
        EXPECT_EQ(sent.payload["ts"],    first["ts"]);
        EXPECT_EQ(sent.payload["seq"],   first["seq"]);

        // members array excludes self.
        const auto& members = sent.payload["members"];
        ASSERT_TRUE(members.is_array());
        for (const auto& m : members) EXPECT_NE(m.get<std::string>(), s_meId);
    }

    // A second send should advance the per-group seq counter.
    m_captured.clear();
    m_gp->sendText("gid", "My Group", {s_meId, s_aliceId}, "again");
    ASSERT_EQ(m_captured.size(), 1U);
    EXPECT_EQ(m_captured[0].payload["seq"].get<int64_t>(), 2);
}

TEST_F(GroupProtocolSuite, SendText_SeqIsPerGroup) {
    m_gp->sendText("gidA", "A", {s_meId, s_aliceId}, "a1");
    m_gp->sendText("gidB", "B", {s_meId, s_aliceId}, "b1");
    m_gp->sendText("gidA", "A", {s_meId, s_aliceId}, "a2");

    // gidA: 1, 2; gidB: 1.
    ASSERT_EQ(m_captured.size(), 3U);
    EXPECT_EQ(m_captured[0].payload["seq"].get<int64_t>(), 1);
    EXPECT_EQ(m_captured[1].payload["seq"].get<int64_t>(), 1);
    EXPECT_EQ(m_captured[2].payload["seq"].get<int64_t>(), 2);
}

TEST_F(GroupProtocolSuite, SendLeave_IncludesSelfInMembersArray) {
    m_gp->sendLeave("gid", "My Group", {s_meId, s_aliceId, s_bobId});

    // group_leave fans out to everyone BUT self.
    ASSERT_EQ(m_captured.size(), 2U);
    EXPECT_EQ(countTo(s_meId), 0);

    // Unlike group_msg, the `members` array on group_leave keeps self so
    // receivers can update their local roster accordingly.
    const auto& members = m_captured[0].payload["members"];
    ASSERT_TRUE(members.is_array());
    bool sawSelf = false;
    for (const auto& m : members)
        if (m.get<std::string>() == s_meId) sawSelf = true;
    EXPECT_TRUE(sawSelf);
    EXPECT_EQ(m_captured[0].payload["type"], "group_leave");
}

TEST_F(GroupProtocolSuite, SendRename_FansToEveryListedKey) {
    // sendRename doesn't filter self — the caller is expected to pass the
    // full member list and ChatController drops own-echoes in the inbound
    // dedup layer.
    m_gp->sendRename("gid", "New Name", {s_aliceId, s_bobId});
    ASSERT_EQ(m_captured.size(), 2U);
    EXPECT_EQ(m_captured[0].payload["type"],    "group_rename");
    EXPECT_EQ(m_captured[0].payload["newName"], "New Name");
    EXPECT_EQ(m_captured[0].payload["groupId"], "gid");
    EXPECT_EQ(m_captured[0].payload["from"],    s_meId);
    // Every fan-out shares the same msgId since it's one logical action.
    EXPECT_EQ(m_captured[0].payload["msgId"], m_captured[1].payload["msgId"]);
}

TEST_F(GroupProtocolSuite, SendAvatar_FansToEveryListedKey) {
    m_gp->sendAvatar("gid", "base64-avatar-bytes", {s_aliceId, s_bobId});
    ASSERT_EQ(m_captured.size(), 2U);
    EXPECT_EQ(m_captured[0].payload["type"],   "group_avatar");
    EXPECT_EQ(m_captured[0].payload["avatar"], "base64-avatar-bytes");
    EXPECT_EQ(m_captured[0].payload["msgId"], m_captured[1].payload["msgId"]);
}

TEST_F(GroupProtocolSuite, SendMemberUpdate_ExcludesSelfFromMembersArrayAndRecipients) {
    m_gp->sendMemberUpdate("gid", "My Group", {s_meId, s_aliceId, s_bobId});

    // Recipients exclude self.
    ASSERT_EQ(m_captured.size(), 2U);
    EXPECT_EQ(countTo(s_meId), 0);

    // members array matches group_msg convention (excludes self) — this
    // is what enables non-creator members to learn their own inclusion
    // from the `from` field rather than the list.
    for (const auto& sent : m_captured) {
        EXPECT_EQ(sent.payload["type"], "group_member_update");
        const auto& members = sent.payload["members"];
        ASSERT_TRUE(members.is_array());
        for (const auto& m : members) EXPECT_NE(m.get<std::string>(), s_meId);
    }
}

TEST_F(GroupProtocolSuite, SendMethodsNoopWithoutSendSealedFn) {
    GroupProtocol bare(*s_meCrypto);  // no setSendSealedFn
    // None of these should throw / crash.
    bare.sendText("gid", "n", {s_aliceId}, "hi");
    bare.sendLeave("gid", "n", {s_aliceId});
    bare.sendRename("gid", "new", {s_aliceId});
    bare.sendAvatar("gid", "a", {s_aliceId});
    bare.sendMemberUpdate("gid", "n", {s_aliceId});
    SUCCEED();
}

TEST_F(GroupProtocolSuite, SendText_TrimsWhitespaceInMemberKeys) {
    // UI copy-paste sometimes adds stray whitespace around a key; the
    // fan-out normalizes before comparing against self.
    const std::string meWithNewline = "\n" + s_meId + "\n";
    m_gp->sendText("gid", "ws",
                   {meWithNewline, "  " + s_aliceId + "  "},
                   "trim me");
    ASSERT_EQ(m_captured.size(), 1U);
    EXPECT_EQ(m_captured[0].peerId, s_aliceId);
    EXPECT_EQ(countTo(s_meId), 0);
}

TEST_F(GroupProtocolSuite, SendText_SkipsEmptyPeerIds) {
    m_gp->sendText("gid", "n", {s_meId, s_aliceId, "", "   "}, "hi");
    ASSERT_EQ(m_captured.size(), 1U);
    EXPECT_EQ(m_captured[0].peerId, s_aliceId);
}
