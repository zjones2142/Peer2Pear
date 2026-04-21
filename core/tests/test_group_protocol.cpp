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
#include "SessionStore.hpp"
#include "SqlCipherDb.hpp"
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
using p2p_test::makeTempPath;

SqlCipherDb::Bytes randomKey32() {
    SqlCipherDb::Bytes k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

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
        s_meCrypto->setPassphrase(p2p_test::kTestPassphrase);
        ASSERT_NO_THROW(s_meCrypto->ensureIdentity());

        s_aliceCrypto = std::make_unique<CryptoEngine>();
        s_aliceCrypto->setDataDir(s_aliceDir);
        s_aliceCrypto->setPassphrase(p2p_test::kTestPassphrase);
        ASSERT_NO_THROW(s_aliceCrypto->ensureIdentity());

        s_bobCrypto = std::make_unique<CryptoEngine>();
        s_bobCrypto->setDataDir(s_bobDir);
        s_bobCrypto->setPassphrase(p2p_test::kTestPassphrase);
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

    // Count fan-outs of a specific message type that targeted a peer.
    // The first sendText to a group fans out both a group_skey_announce
    // and a group_msg to each member, so assertions need to distinguish
    // by type.
    int countTypeTo(const std::string& type,
                    const std::string& peerId) const {
        return int(std::count_if(m_captured.begin(), m_captured.end(),
            [&](const CapturedSend& c) {
                return c.peerId == peerId &&
                       c.payload.value("type", std::string()) == type;
            }));
    }

    // Collect every captured payload of a given type, preserving
    // capture order.  Used to verify per-group_msg metadata (skey_idx,
    // ciphertext, shared msgId, etc.) without tripping over interleaved
    // skey_announce payloads.
    std::vector<nlohmann::json> capturedOfType(const std::string& type) const {
        std::vector<nlohmann::json> out;
        for (const auto& c : m_captured) {
            if (c.payload.value("type", std::string()) == type)
                out.push_back(c.payload);
        }
        return out;
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

TEST_F(GroupProtocolSuite, SendText_FanoutExcludesSelfAdvancesSkeyIdx) {
    m_gp->sendText("gid", "My Group",
                   {s_meId, s_aliceId, s_bobId},
                   "hello all");

    // First send: one skey_announce + one group_msg per non-self peer.
    // 2 + 2 = 4 total captures; self is filtered from both.
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId),   1);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_meId),    0);
    EXPECT_EQ(countTypeTo("group_msg", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_msg", s_bobId),   1);
    EXPECT_EQ(countTypeTo("group_msg", s_meId),    0);

    // Inspect the group_msg payloads: all share the metadata that
    // identifies them as one logical message, and none carry the
    // pre-refactor `text` / `seq` fields.
    auto msgs = capturedOfType("group_msg");
    ASSERT_EQ(msgs.size(), 2U);

    const auto& first = msgs[0];
    EXPECT_EQ(first["type"],      "group_msg");
    EXPECT_EQ(first["groupId"],   "gid");
    EXPECT_EQ(first["groupName"], "My Group");
    EXPECT_EQ(first["from"],      s_meId);
    EXPECT_EQ(first["skey_epoch"].get<uint64_t>(), 0U);
    EXPECT_EQ(first["skey_idx"].get<uint32_t>(), 0U);
    EXPECT_FALSE(first.contains("text")) << "plaintext leaked into group_msg";
    EXPECT_FALSE(first.contains("seq"))  << "seq should not be present on group_msg";
    ASSERT_TRUE(first.contains("ciphertext"));
    EXPECT_FALSE(first["ciphertext"].get<std::string>().empty());

    for (const auto& m : msgs) {
        EXPECT_EQ(m["msgId"],      first["msgId"]);
        EXPECT_EQ(m["ts"],         first["ts"]);
        EXPECT_EQ(m["ciphertext"], first["ciphertext"]);
        EXPECT_EQ(m["skey_idx"],   first["skey_idx"]);
        EXPECT_EQ(m["skey_epoch"], first["skey_epoch"]);

        // members array still excludes self.
        const auto& members = m["members"];
        ASSERT_TRUE(members.is_array());
        for (const auto& k : members) EXPECT_NE(k.get<std::string>(), s_meId);
    }

    // A second send must NOT re-announce the chain, and skey_idx
    // advances inside the existing epoch.
    m_captured.clear();
    m_gp->sendText("gid", "My Group", {s_meId, s_aliceId}, "again");

    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 0);
    auto msgs2 = capturedOfType("group_msg");
    ASSERT_EQ(msgs2.size(), 1U);
    EXPECT_EQ(msgs2[0]["skey_idx"].get<uint32_t>(),   1U);
    EXPECT_EQ(msgs2[0]["skey_epoch"].get<uint64_t>(), 0U);
}

TEST_F(GroupProtocolSuite, SendText_SkeyIdxIsPerGroup) {
    m_gp->sendText("gidA", "A", {s_meId, s_aliceId}, "a1");
    m_gp->sendText("gidB", "B", {s_meId, s_aliceId}, "b1");
    m_gp->sendText("gidA", "A", {s_meId, s_aliceId}, "a2");

    // Each group has its own SenderChain — per-group independent
    // skey_idx counters that count from 0.
    auto msgs = capturedOfType("group_msg");
    ASSERT_EQ(msgs.size(), 3U);
    EXPECT_EQ(msgs[0]["groupId"], "gidA");
    EXPECT_EQ(msgs[0]["skey_idx"].get<uint32_t>(), 0U);
    EXPECT_EQ(msgs[1]["groupId"], "gidB");
    EXPECT_EQ(msgs[1]["skey_idx"].get<uint32_t>(), 0U);
    EXPECT_EQ(msgs[2]["groupId"], "gidA");
    EXPECT_EQ(msgs[2]["skey_idx"].get<uint32_t>(), 1U);
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

TEST_F(GroupProtocolSuite, SendRename_EncryptsNewNameFansToNonSelf) {
    // sendRename now filters self (consistent with group_msg fan-out)
    // and encrypts newName inside a sender-chain ciphertext.  First
    // call to any group-send lazy-creates the chain, so we expect an
    // announce to each recipient too.
    m_gp->sendRename("gid", "New Name", {s_meId, s_aliceId, s_bobId});

    auto renames = capturedOfType("group_rename");
    ASSERT_EQ(renames.size(), 2U);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId),   1);
    EXPECT_EQ(countTypeTo("group_rename",        s_meId),    0);

    for (const auto& r : renames) {
        EXPECT_EQ(r["type"],    "group_rename");
        EXPECT_EQ(r["groupId"], "gid");
        EXPECT_EQ(r["from"],    s_meId);
        EXPECT_FALSE(r.contains("newName")) << "plaintext newName leaked";
        ASSERT_TRUE(r.contains("ciphertext"));
        EXPECT_FALSE(r["ciphertext"].get<std::string>().empty());
    }
    // Every fan-out shares the same msgId + ciphertext (one logical action).
    EXPECT_EQ(renames[0]["msgId"],      renames[1]["msgId"]);
    EXPECT_EQ(renames[0]["ciphertext"], renames[1]["ciphertext"]);
}

TEST_F(GroupProtocolSuite, SendAvatar_EncryptsAvatarFansToNonSelf) {
    m_gp->sendAvatar("gid", "base64-avatar-bytes", {s_meId, s_aliceId, s_bobId});

    auto avatars = capturedOfType("group_avatar");
    ASSERT_EQ(avatars.size(), 2U);
    for (const auto& a : avatars) {
        EXPECT_EQ(a["type"], "group_avatar");
        EXPECT_FALSE(a.contains("avatar")) << "plaintext avatar leaked";
        ASSERT_TRUE(a.contains("ciphertext"));
    }
    EXPECT_EQ(avatars[0]["msgId"],      avatars[1]["msgId"]);
    EXPECT_EQ(avatars[0]["ciphertext"], avatars[1]["ciphertext"]);
}

TEST_F(GroupProtocolSuite, SendMemberUpdate_EncryptsGroupNameAndMembers) {
    m_gp->sendMemberUpdate("gid", "My Group", {s_meId, s_aliceId, s_bobId});

    auto updates = capturedOfType("group_member_update");
    ASSERT_EQ(updates.size(), 2U);
    EXPECT_EQ(countTo(s_meId), 0);

    for (const auto& u : updates) {
        EXPECT_EQ(u["type"], "group_member_update");
        EXPECT_FALSE(u.contains("groupName")) << "plaintext groupName leaked";
        EXPECT_FALSE(u.contains("members"))   << "plaintext members leaked";
        ASSERT_TRUE(u.contains("ciphertext"));
    }
}

TEST_F(GroupProtocolSuite, SendRename_RoundTripDecryptsToNewName) {
    // End-to-end: peer installs chain from the captured announce,
    // then decrypts the captured rename ciphertext to recover newName.
    m_gp->sendRename("gid", "Fresh Title", {s_meId, s_aliceId});

    auto announces = capturedOfType("group_skey_announce");
    auto renames   = capturedOfType("group_rename");
    ASSERT_EQ(announces.size(), 1U);
    ASSERT_EQ(renames.size(),   1U);

    GroupProtocol peer(*s_aliceCrypto);
    peer.installRemoteChain("gid", s_meId,
        announces[0]["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(announces[0]["seed"].get<std::string>()));

    Bytes pt = peer.decryptGroupMessage("group_rename", "gid", s_meId,
        renames[0]["skey_epoch"].get<uint64_t>(),
        renames[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(renames[0]["ciphertext"].get<std::string>()));
    ASSERT_FALSE(pt.empty());
    auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
    EXPECT_EQ(inner.value("newName", std::string()), "Fresh Title");
}

TEST_F(GroupProtocolSuite, AadBindsTypeAgainstCrossTypeReplay) {
    // A ciphertext produced for "group_msg" must NOT decrypt as
    // "group_rename" — AAD includes the wire type so AEAD auth
    // rejects the substitution.
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "hello");

    auto announces = capturedOfType("group_skey_announce");
    auto msgs      = capturedOfType("group_msg");
    ASSERT_EQ(announces.size(), 1U);
    ASSERT_EQ(msgs.size(),      1U);

    GroupProtocol peer(*s_aliceCrypto);
    peer.installRemoteChain("gid", s_meId,
        announces[0]["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(announces[0]["seed"].get<std::string>()));

    const Bytes ct = CryptoEngine::fromBase64Url(
        msgs[0]["ciphertext"].get<std::string>());

    // Correct type decrypts cleanly.
    Bytes ok = peer.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs[0]["skey_epoch"].get<uint64_t>(),
        msgs[0]["skey_idx"].get<uint32_t>(), ct);
    EXPECT_FALSE(ok.empty());

    // Wrong type fails cleanly — AEAD auth trips because AAD differs.
    for (const std::string& wrongType :
         {"group_rename", "group_avatar", "group_member_update"}) {
        Bytes fail = peer.decryptGroupMessage(wrongType, "gid", s_meId,
            msgs[0]["skey_epoch"].get<uint64_t>(),
            msgs[0]["skey_idx"].get<uint32_t>(), ct);
        EXPECT_TRUE(fail.empty()) << "ciphertext decrypted as " << wrongType;
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
    // fan-out normalizes before comparing against self.  First send
    // fans BOTH a skey_announce and a group_msg to each non-self peer.
    const std::string meWithNewline = "\n" + s_meId + "\n";
    m_gp->sendText("gid", "ws",
                   {meWithNewline, "  " + s_aliceId + "  "},
                   "trim me");

    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_msg", s_aliceId), 1);
    EXPECT_EQ(countTo(s_meId), 0);
}

TEST_F(GroupProtocolSuite, SendText_SkipsEmptyPeerIds) {
    m_gp->sendText("gid", "n", {s_meId, s_aliceId, "", "   "}, "hi");
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_msg", s_aliceId), 1);
    EXPECT_EQ(countTo(s_meId), 0);
}

// ── 5. Sender-chain outbound wire format ────────────────────────────────────

TEST_F(GroupProtocolSuite, MyEpochAndHasMyChain_DefaultState) {
    // Before any send: no outbound chain exists for any group.
    EXPECT_FALSE(m_gp->hasMyChain("gid"));
    EXPECT_EQ(m_gp->myEpoch("gid"), 0U);
    EXPECT_EQ(m_gp->outboundChainCount(), 0U);
    EXPECT_EQ(m_gp->inboundChainCount(),  0U);
}

TEST_F(GroupProtocolSuite, SendText_LazyCreatesOutboundChainOnFirstSend) {
    ASSERT_FALSE(m_gp->hasMyChain("gid"));
    m_gp->sendText("gid", "name", {s_meId, s_aliceId}, "first");
    EXPECT_TRUE(m_gp->hasMyChain("gid"));
    EXPECT_EQ(m_gp->myEpoch("gid"), 0U);
    EXPECT_EQ(m_gp->outboundChainCount(), 1U);
}

TEST_F(GroupProtocolSuite, SendSkeyAnnounce_PayloadShapeIsCorrect) {
    m_gp->sendText("gid", "name", {s_meId, s_aliceId}, "trigger");

    auto announces = capturedOfType("group_skey_announce");
    ASSERT_EQ(announces.size(), 1U);
    const auto& a = announces[0];

    EXPECT_EQ(a["type"],    "group_skey_announce");
    EXPECT_EQ(a["from"],    s_meId);
    EXPECT_EQ(a["groupId"], "gid");
    EXPECT_EQ(a["epoch"].get<uint64_t>(), 0U);
    ASSERT_TRUE(a.contains("seed"));
    const std::string seedB64 = a["seed"].get<std::string>();

    // Seed is base64url 32 bytes; 32 bytes → 43 unpadded base64url chars.
    const Bytes seedBytes = CryptoEngine::fromBase64Url(seedB64);
    EXPECT_EQ(seedBytes.size(), 32U);

    ASSERT_TRUE(a.contains("ts"));
    ASSERT_TRUE(a.contains("msgId"));
}

TEST_F(GroupProtocolSuite, SendText_SkeyAnnouncePrecedesGroupMsg) {
    // For each non-self peer, the announce must be captured before
    // the group_msg.  The per-peer 1:1 ratchet delivers FIFO, so if
    // our send order is announce-before-msg, the receiver also sees
    // them in that order.
    m_gp->sendText("gid", "name", {s_meId, s_aliceId, s_bobId}, "hi");

    // First two captures for each peer should be announce then msg.
    // Walk the capture list and verify the pattern per-peer.
    auto firstIdxOf = [&](const std::string& type, const std::string& peer) {
        for (size_t i = 0; i < m_captured.size(); ++i) {
            const auto& c = m_captured[i];
            if (c.peerId == peer &&
                c.payload.value("type", std::string()) == type)
                return int(i);
        }
        return -1;
    };
    const int aliceAnnounce = firstIdxOf("group_skey_announce", s_aliceId);
    const int aliceMsg      = firstIdxOf("group_msg",           s_aliceId);
    const int bobAnnounce   = firstIdxOf("group_skey_announce", s_bobId);
    const int bobMsg        = firstIdxOf("group_msg",           s_bobId);
    ASSERT_GE(aliceAnnounce, 0);
    ASSERT_GE(aliceMsg,      0);
    ASSERT_GE(bobAnnounce,   0);
    ASSERT_GE(bobMsg,        0);
    EXPECT_LT(aliceAnnounce, aliceMsg);
    EXPECT_LT(bobAnnounce,   bobMsg);
}

TEST_F(GroupProtocolSuite, SendText_FanoutCiphertextIdenticalForAllMembers) {
    // The whole point of Sender Keys: one encrypt op, identical inner
    // ciphertext for every recipient.  Per-peer differences live only
    // in the outer 1:1 sealed envelope that our mock m_sendSealed
    // stands in for — the inner payload we capture here must match
    // byte-for-byte across members.
    m_gp->sendText("gid", "n", {s_meId, s_aliceId, s_bobId}, "same bytes");

    auto msgs = capturedOfType("group_msg");
    ASSERT_EQ(msgs.size(), 2U);
    EXPECT_EQ(msgs[0]["ciphertext"], msgs[1]["ciphertext"]);
    EXPECT_EQ(msgs[0]["skey_idx"],   msgs[1]["skey_idx"]);
    EXPECT_EQ(msgs[0]["skey_epoch"], msgs[1]["skey_epoch"]);
    EXPECT_EQ(msgs[0]["msgId"],      msgs[1]["msgId"]);
}

// ── 6. Sender-chain inbound decrypt path ────────────────────────────────────

TEST_F(GroupProtocolSuite, InstallRemoteChain_TrackedInInboundCount) {
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes(32, 0xAA));
    EXPECT_EQ(m_gp->inboundChainCount(), 1U);
    // Different sender in same group → separate chain.
    m_gp->installRemoteChain("gid", s_bobId,   0, Bytes(32, 0xBB));
    EXPECT_EQ(m_gp->inboundChainCount(), 2U);
    // Same (gid, sender) → overwrite, not add.
    m_gp->installRemoteChain("gid", s_aliceId, 1, Bytes(32, 0xCC));
    EXPECT_EQ(m_gp->inboundChainCount(), 2U);
}

TEST_F(GroupProtocolSuite, InstallRemoteChain_RejectsInvalidSeed) {
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
    // 16-byte seed → rejected, no entry added.
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes(16, 0x11));
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
    // Empty seed → rejected.
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes{});
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
    // Empty gid / senderId → rejected regardless of seed.
    m_gp->installRemoteChain("",    s_aliceId, 0, Bytes(32, 0x11));
    m_gp->installRemoteChain("gid", "",        0, Bytes(32, 0x11));
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
}

TEST_F(GroupProtocolSuite, ForgetRemoteChain_RemovesEntry) {
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes(32, 0xAA));
    EXPECT_EQ(m_gp->inboundChainCount(), 1U);
    m_gp->forgetRemoteChain("gid", s_aliceId);
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
    // Idempotent — forgetting an unknown peer is a no-op.
    m_gp->forgetRemoteChain("gid", "never-installed");
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_WithoutChainReturnsEmpty) {
    // No chain installed for this (gid, sender) — decrypt fails
    // cleanly without crashing.
    Bytes fakeCiphertext(64, 0x42);
    Bytes pt = m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId, 0, 0,
                                           fakeCiphertext);
    EXPECT_TRUE(pt.empty());
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_StaleEpochReturnsEmpty) {
    // Chain installed at epoch 0; message claims epoch 1.  Without a
    // grace-window prev chain for epoch 1 (none was installed),
    // decryption rejects the epoch mismatch cleanly.
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes(32, 0xAA));
    Bytes ct(64, 0x42);
    Bytes pt = m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId, 1, 0, ct);
    EXPECT_TRUE(pt.empty());
    // Same epoch but bogus ciphertext → also empty, but for a
    // different reason (AEAD auth fail, not epoch check).
    Bytes pt2 = m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId, 0, 0, ct);
    EXPECT_TRUE(pt2.empty());
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_RoundTripMatchesPlaintext) {
    // The load-bearing sender-keys round-trip: Alice's local
    // GroupProtocol sends a text; Me installs Alice's chain from the
    // captured skey_announce; Me's decryptGroupMessage on the captured
    // ciphertext recovers the plaintext.
    //
    // Uses a locally-constructed GroupProtocol for Alice's side so we
    // have two independent chain-state owners.
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) {
            aliceCaptured.push_back({peer, payload});
        });

    // Alice sends "greetings" to a group with me and bob.
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId, s_bobId}, "greetings");

    // Extract Alice's announce addressed to me.
    nlohmann::json announceToMe;
    nlohmann::json msgToMe;
    for (const auto& c : aliceCaptured) {
        if (c.peerId != s_meId) continue;
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce") announceToMe = c.payload;
        if (t == "group_msg")            msgToMe      = c.payload;
    }
    ASSERT_FALSE(announceToMe.is_null());
    ASSERT_FALSE(msgToMe.is_null());

    // Me installs Alice's chain from the announce.
    const Bytes seed = CryptoEngine::fromBase64Url(
        announceToMe["seed"].get<std::string>());
    ASSERT_EQ(seed.size(), 32U);
    m_gp->installRemoteChain("gid", s_aliceId,
                              announceToMe["epoch"].get<uint64_t>(), seed);

    // Me decrypts Alice's group_msg ciphertext.
    const Bytes ct = CryptoEngine::fromBase64Url(
        msgToMe["ciphertext"].get<std::string>());
    Bytes pt = m_gp->decryptGroupMessage(
        "group_msg", "gid", s_aliceId,
        msgToMe["skey_epoch"].get<uint64_t>(),
        msgToMe["skey_idx"].get<uint32_t>(),
        ct);

    ASSERT_FALSE(pt.empty());
    auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
    EXPECT_EQ(inner.value("text", std::string()), "greetings");
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_TamperedCiphertextReturnsEmpty) {
    // Capture Alice's outbound message, flip a bit in the ciphertext,
    // then verify me's decrypt fails.  AAD binding makes the tampered
    // ciphertext cryptographically distinct from any valid one at
    // (from, gid, epoch, idx).
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) {
            aliceCaptured.push_back({peer, payload});
        });
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "untampered");

    nlohmann::json announce, msg;
    for (const auto& c : aliceCaptured) {
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce") announce = c.payload;
        if (t == "group_msg")            msg      = c.payload;
    }
    ASSERT_FALSE(announce.is_null());
    ASSERT_FALSE(msg.is_null());

    m_gp->installRemoteChain("gid", s_aliceId,
                              announce["epoch"].get<uint64_t>(),
                              CryptoEngine::fromBase64Url(
                                  announce["seed"].get<std::string>()));

    Bytes ct = CryptoEngine::fromBase64Url(
        msg["ciphertext"].get<std::string>());
    // Flip a bit in the ciphertext payload (past the 24-byte nonce).
    ASSERT_GT(ct.size(), 25U);
    ct[25] ^= 0x01;

    Bytes pt = m_gp->decryptGroupMessage(
        "group_msg", "gid", s_aliceId,
        msg["skey_epoch"].get<uint64_t>(),
        msg["skey_idx"].get<uint32_t>(),
        ct);
    EXPECT_TRUE(pt.empty());
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_WrongSenderIdBreaksAad) {
    // AAD binds the sender identity.  A ciphertext produced by Alice
    // cannot be decrypted as if it came from Bob — even if Bob happens
    // to have Alice's chain installed (he shouldn't, but we enforce
    // defence-in-depth at the AEAD layer).
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) {
            aliceCaptured.push_back({peer, payload});
        });
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "from alice");

    nlohmann::json announce, msg;
    for (const auto& c : aliceCaptured) {
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce") announce = c.payload;
        if (t == "group_msg")            msg      = c.payload;
    }
    const Bytes seed = CryptoEngine::fromBase64Url(
        announce["seed"].get<std::string>());

    // Install Alice's chain under BOB's peer_id — attacker scenario:
    // someone tries to attribute Alice's message to Bob.
    m_gp->installRemoteChain("gid", s_bobId,
                              announce["epoch"].get<uint64_t>(), seed);

    const Bytes ct = CryptoEngine::fromBase64Url(
        msg["ciphertext"].get<std::string>());
    // AAD uses s_bobId (not s_aliceId) — mismatches the sender-side AAD.
    Bytes pt = m_gp->decryptGroupMessage(
        "group_msg", "gid", s_bobId,
        msg["skey_epoch"].get<uint64_t>(),
        msg["skey_idx"].get<uint32_t>(),
        ct);
    EXPECT_TRUE(pt.empty());
}

// ── 7. Persistence of outbound chain ─────────────────────────────────────

TEST_F(GroupProtocolSuite, SerializeRestoreMyChain_PreservesDecryption) {
    // Me sends one message to establish a chain, serializes the chain,
    // destroys state, restores, sends another message from the
    // restored chain.  A local peer with the original announce's seed
    // installed must be able to decrypt both messages.

    // Send #1 with the original chain.
    m_gp->sendText("gid", "n", {s_meId, s_aliceId}, "before-restore");
    auto msgs1 = capturedOfType("group_msg");
    auto anns1 = capturedOfType("group_skey_announce");
    ASSERT_EQ(msgs1.size(), 1U);
    ASSERT_EQ(anns1.size(), 1U);

    // Snapshot chain state.
    const Bytes blob = m_gp->serializeMyChain("gid");
    ASSERT_FALSE(blob.empty());
    const uint64_t epoch = m_gp->myEpoch("gid");
    EXPECT_EQ(epoch, 0U);

    // Destroy + recreate the protocol object (simulating restart).
    m_gp = std::make_unique<GroupProtocol>(*s_meCrypto);
    m_captured.clear();
    m_gp->setSendSealedFn(
        [this](const std::string& p, const nlohmann::json& pl) {
            m_captured.push_back({p, pl});
        });
    EXPECT_FALSE(m_gp->hasMyChain("gid"));

    m_gp->restoreMyChain("gid", epoch, blob);
    EXPECT_TRUE(m_gp->hasMyChain("gid"));
    EXPECT_EQ(m_gp->myEpoch("gid"), 0U);

    // Next sendText must NOT generate a new skey_announce — the chain
    // is already established from before.  And skey_idx must continue
    // from where the original chain left off (idx=1, not 0).
    m_gp->sendText("gid", "n", {s_meId, s_aliceId}, "after-restore");
    auto msgs2 = capturedOfType("group_msg");
    auto anns2 = capturedOfType("group_skey_announce");
    ASSERT_EQ(msgs2.size(), 1U);
    EXPECT_EQ(anns2.size(),  0U) << "restored chain should not re-announce";
    EXPECT_EQ(msgs2[0]["skey_idx"].get<uint32_t>(), 1U);

    // Install the SAME seed on a peer's perspective to decrypt both.
    GroupProtocol peer(*s_aliceCrypto);
    const Bytes seed = CryptoEngine::fromBase64Url(
        anns1[0]["seed"].get<std::string>());
    peer.installRemoteChain("gid", s_meId, 0, seed);

    Bytes pt1 = peer.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs1[0]["skey_epoch"].get<uint64_t>(),
        msgs1[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msgs1[0]["ciphertext"].get<std::string>()));
    Bytes pt2 = peer.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs2[0]["skey_epoch"].get<uint64_t>(),
        msgs2[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msgs2[0]["ciphertext"].get<std::string>()));

    auto inner1 = nlohmann::json::parse(std::string(pt1.begin(), pt1.end()));
    auto inner2 = nlohmann::json::parse(std::string(pt2.begin(), pt2.end()));
    EXPECT_EQ(inner1.value("text", std::string()), "before-restore");
    EXPECT_EQ(inner2.value("text", std::string()), "after-restore");
}

TEST_F(GroupProtocolSuite, SerializeMyChain_EmptyForUnknownGroup) {
    // No chain has been created — serialize returns empty (not a
    // zero-size valid blob, just empty bytes).
    EXPECT_TRUE(m_gp->serializeMyChain("never-existed").empty());
}

TEST_F(GroupProtocolSuite, RestoreMyChain_InvalidBlobRejected) {
    m_gp->restoreMyChain("gid", 0, Bytes{0xDE, 0xAD, 0xBE, 0xEF});
    EXPECT_FALSE(m_gp->hasMyChain("gid"));
    EXPECT_EQ(m_gp->outboundChainCount(), 0U);
}

// ── 8. Rekey-on-leave + grace window ────────────────────────────────────────

TEST_F(GroupProtocolSuite, RotateMyChain_BumpsEpochAndAnnouncesToRemaining) {
    // Establish initial chain via a first send.
    m_gp->sendText("gid", "G", {s_meId, s_aliceId, s_bobId}, "hello");
    ASSERT_EQ(m_gp->myEpoch("gid"), 0U);
    m_captured.clear();

    // Rotate excluding bob — announces should go only to alice.
    m_gp->rotateMyChain("gid", {s_meId, s_aliceId});

    EXPECT_EQ(m_gp->myEpoch("gid"), 1U);
    auto announces = capturedOfType("group_skey_announce");
    ASSERT_EQ(announces.size(), 1U);
    EXPECT_EQ(m_captured[0].peerId, s_aliceId);
    EXPECT_EQ(announces[0]["epoch"].get<uint64_t>(), 1U);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId), 0)
        << "rotated seed must NOT be announced to the removed peer";
}

TEST_F(GroupProtocolSuite, RotateMyChain_NoopWhenNoChainExists) {
    // Never sent anything for this group — rotate is a no-op.
    EXPECT_FALSE(m_gp->hasMyChain("gid"));
    m_gp->rotateMyChain("gid", {s_meId, s_aliceId});
    EXPECT_FALSE(m_gp->hasMyChain("gid"));
    EXPECT_EQ(m_gp->myEpoch("gid"), 0U);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 0);
}

TEST_F(GroupProtocolSuite, RotateMyChain_SubsequentSendUsesNewEpoch) {
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "first");
    m_captured.clear();

    m_gp->rotateMyChain("gid", {s_meId, s_aliceId});
    m_captured.clear();

    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "after rekey");
    auto msgs = capturedOfType("group_msg");
    ASSERT_EQ(msgs.size(), 1U);
    EXPECT_EQ(msgs[0]["skey_epoch"].get<uint64_t>(), 1U);
    EXPECT_EQ(msgs[0]["skey_idx"].get<uint32_t>(),   0U)
        << "post-rotate chain restarts its own idx counter";
}

TEST_F(GroupProtocolSuite, SendMemberUpdate_RotatesOnRemoval) {
    // Seed roster + outbound chain via a first send.
    m_gp->sendText("gid", "G", {s_meId, s_aliceId, s_bobId}, "setup");
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId, s_bobId});
    ASSERT_EQ(m_gp->myEpoch("gid"), 0U);
    m_captured.clear();

    // Drop Bob from the roster.
    m_gp->sendMemberUpdate("gid", "G", {s_meId, s_aliceId});

    // Epoch bumped → chain rotated.
    EXPECT_EQ(m_gp->myEpoch("gid"), 1U);
    // Fresh announce to Alice only (Bob is the removed peer).
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId),   0);
    // Control message (group_member_update) goes to Alice only — Bob
    // is explicitly excluded from the new roster.
    EXPECT_EQ(countTypeTo("group_member_update", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_member_update", s_bobId),   0);
}

TEST_F(GroupProtocolSuite, SendMemberUpdate_AnnouncesCurrentChainToAddedMember) {
    // Seed roster + outbound chain via a first send (me + alice).
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "hi alice");
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId});
    ASSERT_EQ(m_gp->myEpoch("gid"), 0U);
    m_captured.clear();

    // Add bob — no removal, so no rotation.
    m_gp->sendMemberUpdate("gid", "G", {s_meId, s_aliceId, s_bobId});

    // Epoch unchanged.
    EXPECT_EQ(m_gp->myEpoch("gid"), 0U);
    // Current-epoch seed announced to the NEW member (bob) only.
    // Alice already had it from the original first send.
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId),   1);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 0);
    // Control message fans to both.
    EXPECT_EQ(countTypeTo("group_member_update", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_member_update", s_bobId),   1);
}

TEST_F(GroupProtocolSuite, SendMemberUpdate_NoOpRosterNoRotateNoAnnounce) {
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "hi");
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId});
    ASSERT_EQ(m_gp->myEpoch("gid"), 0U);
    m_captured.clear();

    // Unchanged roster — no rotate, no re-announce.  Just the control
    // fan-out.
    m_gp->sendMemberUpdate("gid", "G", {s_meId, s_aliceId});

    EXPECT_EQ(m_gp->myEpoch("gid"), 0U);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 0);
    EXPECT_EQ(countTypeTo("group_member_update", s_aliceId), 1);
}

TEST_F(GroupProtocolSuite, InstallRemoteChain_SecondInstallMovesCurrentToPrev) {
    // First announce at epoch 0.
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes(32, 0xA0));

    // Second announce at epoch 1 (simulating Alice rotating after
    // removing someone).  The epoch 0 chain should NOT be discarded
    // outright — it should move to the grace-window prev slot so any
    // in-flight epoch-0 messages still decrypt.
    m_gp->installRemoteChain("gid", s_aliceId, 1, Bytes(32, 0xB0));

    // Still one inbound entry per (gid, sender) — the prev chain
    // lives inside that single entry, not as a separate map row.
    EXPECT_EQ(m_gp->inboundChainCount(), 1U);
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_PrevEpochWithinGraceWorks) {
    // Alice sends msg at epoch 0, then rotates + sends at epoch 1.
    // Me receives both announces + both messages.  The epoch-0 message
    // must still decrypt during the grace window via the prev chain.
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) {
            aliceCaptured.push_back({peer, payload});
        });

    // Epoch 0: first send + its announce.
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg at epoch 0");
    // Epoch 1: rotate, then another send.
    aliceGp.rotateMyChain("gid", {s_aliceId, s_meId});
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg at epoch 1");

    // Replay Alice's captured traffic through me's GroupProtocol IN
    // ORDER (announce-0, msg-0, announce-1, msg-1).  After the
    // epoch-1 announce, me's prev slot should hold the epoch-0 chain.
    auto findOfType = [&](const std::string& type, size_t fromIdx) -> size_t {
        for (size_t i = fromIdx; i < aliceCaptured.size(); ++i) {
            if (aliceCaptured[i].peerId != s_meId) continue;
            if (aliceCaptured[i].payload.value("type", std::string()) == type)
                return i;
        }
        return aliceCaptured.size();
    };

    // Install the epoch-0 chain.
    size_t an0 = findOfType("group_skey_announce", 0);
    ASSERT_LT(an0, aliceCaptured.size());
    m_gp->installRemoteChain("gid", s_aliceId,
        aliceCaptured[an0].payload["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(
            aliceCaptured[an0].payload["seed"].get<std::string>()));

    // Capture the epoch-0 ciphertext for later.
    size_t m0 = findOfType("group_msg", an0 + 1);
    ASSERT_LT(m0, aliceCaptured.size());
    const nlohmann::json msg0 = aliceCaptured[m0].payload;

    // Install the epoch-1 chain — moves epoch-0 chain into prev slot.
    size_t an1 = findOfType("group_skey_announce", m0 + 1);
    ASSERT_LT(an1, aliceCaptured.size());
    m_gp->installRemoteChain("gid", s_aliceId,
        aliceCaptured[an1].payload["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(
            aliceCaptured[an1].payload["seed"].get<std::string>()));

    // Now: decrypt the epoch-0 message using the prev-chain path.
    // Grace window is the class default (5 min) so no time has
    // passed between install and decrypt here.
    Bytes pt = m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId,
        msg0["skey_epoch"].get<uint64_t>(),
        msg0["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msg0["ciphertext"].get<std::string>()));
    ASSERT_FALSE(pt.empty()) << "prev-chain decrypt within grace window failed";
    auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
    EXPECT_EQ(inner.value("text", std::string()), "msg at epoch 0");
}

TEST_F(GroupProtocolSuite, DecryptGroupMessage_PrevEpochAfterGraceExpiresFails) {
    // Same setup as the grace-within test, but we shrink the grace
    // window to 0 before the second install so the prev slot expires
    // immediately.
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) {
            aliceCaptured.push_back({peer, payload});
        });
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg at epoch 0");
    aliceGp.rotateMyChain("gid", {s_aliceId, s_meId});
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg at epoch 1");

    // Install epoch-0 chain first.
    nlohmann::json announce0, announce1, msg0;
    bool sawAn0 = false, sawMsg0 = false;
    for (const auto& c : aliceCaptured) {
        if (c.peerId != s_meId) continue;
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce") {
            if (!sawAn0) { announce0 = c.payload; sawAn0 = true; }
            else         { announce1 = c.payload; }
        } else if (t == "group_msg" && !sawMsg0) {
            msg0 = c.payload; sawMsg0 = true;
        }
    }
    ASSERT_FALSE(announce0.is_null());
    ASSERT_FALSE(announce1.is_null());
    ASSERT_FALSE(msg0.is_null());

    m_gp->installRemoteChain("gid", s_aliceId,
        announce0["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(announce0["seed"].get<std::string>()));

    // Shrink grace window to zero BEFORE the second install so the
    // prev slot's prevExpiresAt == nowSecs() and the check fails
    // immediately on access.
    m_gp->setGraceWindowSecs(0);

    m_gp->installRemoteChain("gid", s_aliceId,
        announce1["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(announce1["seed"].get<std::string>()));

    // Decrypt attempt at epoch 0 should fail — prev slot expired.
    Bytes pt = m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId,
        msg0["skey_epoch"].get<uint64_t>(),
        msg0["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msg0["ciphertext"].get<std::string>()));
    EXPECT_TRUE(pt.empty())
        << "prev-chain decrypt past grace window should fail";
}

TEST_F(GroupProtocolSuite, RemovedPeerCannotDecryptPostRotationMessages) {
    // End-to-end: me has a chain shared with bob.  Me drops bob via
    // sendMemberUpdate (→ rotate).  Me sends a new group_msg at the
    // new epoch.  Bob's held copy of the old chain cannot decrypt
    // the new-epoch ciphertext because (a) the AAD binds the new
    // epoch, and (b) bob was excluded from the re-announce so he
    // doesn't have the new seed.
    m_gp->sendText("gid", "G", {s_meId, s_aliceId, s_bobId}, "hi all");
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId, s_bobId});

    // Capture Bob's view: he installed my epoch-0 chain from the
    // initial skey_announce.
    GroupProtocol bobGp(*s_bobCrypto);
    nlohmann::json announceToBob;
    for (const auto& c : m_captured) {
        if (c.peerId != s_bobId) continue;
        if (c.payload.value("type", std::string()) == "group_skey_announce") {
            announceToBob = c.payload;
            break;
        }
    }
    ASSERT_FALSE(announceToBob.is_null());
    bobGp.installRemoteChain("gid", s_meId,
        announceToBob["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(
            announceToBob["seed"].get<std::string>()));

    // Me removes bob — triggers rotation.
    m_captured.clear();
    m_gp->sendMemberUpdate("gid", "G", {s_meId, s_aliceId});
    ASSERT_EQ(m_gp->myEpoch("gid"), 1U);
    // Bob received NOTHING new (not in the remaining roster).
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId), 0);

    // Me sends a post-rotation message.
    m_captured.clear();
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "secret after rekey");

    // Grab the ciphertext that went to Alice — Bob wouldn't see it
    // over the wire at all, but if somehow it reached him (e.g.,
    // malicious relay leak), his chain still can't decrypt.  Simulate
    // by handing Alice's ciphertext to Bob's decryptGroupMessage.
    auto msgs = capturedOfType("group_msg");
    ASSERT_EQ(msgs.size(), 1U);
    ASSERT_EQ(msgs[0]["skey_epoch"].get<uint64_t>(), 1U);

    Bytes pt = bobGp.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs[0]["skey_epoch"].get<uint64_t>(),
        msgs[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msgs[0]["ciphertext"].get<std::string>()));
    EXPECT_TRUE(pt.empty())
        << "removed peer should not be able to decrypt post-rotation msgs";
}

TEST_F(GroupProtocolSuite, ForgetRemoteChain_ClearsBothCurrentAndPrev) {
    // Two installs back-to-back populate both slots (current + prev).
    m_gp->installRemoteChain("gid", s_aliceId, 0, Bytes(32, 0x11));
    m_gp->installRemoteChain("gid", s_aliceId, 1, Bytes(32, 0x22));
    EXPECT_EQ(m_gp->inboundChainCount(), 1U);

    m_gp->forgetRemoteChain("gid", s_aliceId);
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);

    // Subsequent decrypt attempts at either epoch fail cleanly.
    Bytes anyCt(64, 0x42);
    EXPECT_TRUE(m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId, 0, 0, anyCt).empty());
    EXPECT_TRUE(m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId, 1, 0, anyCt).empty());
}

TEST_F(GroupProtocolSuite, SendMemberUpdate_RemovedPeerChainForgotten) {
    // Seed roster + an inbound chain for bob so we have something to
    // forget.  First sendText establishes my outbound chain for the
    // diff check to trigger rotation later.
    m_gp->sendText("gid", "G", {s_meId, s_aliceId, s_bobId}, "hi");
    m_gp->setKnownMembers("gid", {s_meId, s_aliceId, s_bobId});
    m_gp->installRemoteChain("gid", s_bobId, 0, Bytes(32, 0xBB));
    ASSERT_EQ(m_gp->inboundChainCount(), 1U);

    // Remove bob — his chain should be dropped from our inbound map.
    m_gp->sendMemberUpdate("gid", "G", {s_meId, s_aliceId});
    EXPECT_EQ(m_gp->inboundChainCount(), 0U);
}

// ── 9. Disk-backed persistence via SessionStore ─────────────────────────

// Helper: one-stop setup for a (db, store, gp) triple for a given
// crypto identity.  The store's storeKey is returned so a follow-up
// "restart" can re-open the same DB with the same key.
struct PersistenceFixture {
    std::unique_ptr<SqlCipherDb>   db;
    std::unique_ptr<SessionStore>  store;
    std::unique_ptr<GroupProtocol> gp;
    std::vector<CapturedSend>      captured;
    std::string                    dbPath;
    SqlCipherDb::Bytes             dbKey;
    SqlCipherDb::Bytes             storeKey;
};

static PersistenceFixture makeFixture(CryptoEngine& crypto) {
    PersistenceFixture f;
    f.dbPath   = makeTempPath("p2p-gp-persist", ".db");
    f.dbKey    = randomKey32();
    f.storeKey = randomKey32();

    f.db = std::make_unique<SqlCipherDb>();
    if (!f.db->open(f.dbPath, f.dbKey)) {
        ADD_FAILURE() << "failed to open test DB";
        return f;
    }
    f.store = std::make_unique<SessionStore>(*f.db, f.storeKey);

    f.gp = std::make_unique<GroupProtocol>(crypto);
    f.gp->setSessionStore(f.store.get());
    f.gp->setSendSealedFn(
        [&f](const std::string& peer, const nlohmann::json& payload) {
            f.captured.push_back({peer, payload});
        });
    return f;
}

// Reopen an existing DB + re-wire a fresh GroupProtocol against it.
// Callers hand in the dbPath / dbKey / storeKey from makeFixture.
static PersistenceFixture reopenFixture(CryptoEngine& crypto,
                                          const std::string& dbPath,
                                          const SqlCipherDb::Bytes& dbKey,
                                          const SqlCipherDb::Bytes& storeKey) {
    PersistenceFixture f;
    f.dbPath   = dbPath;
    f.dbKey    = dbKey;
    f.storeKey = storeKey;
    f.db = std::make_unique<SqlCipherDb>();
    if (!f.db->open(f.dbPath, f.dbKey)) {
        ADD_FAILURE() << "failed to reopen test DB";
        return f;
    }
    f.store = std::make_unique<SessionStore>(*f.db, f.storeKey);
    f.gp = std::make_unique<GroupProtocol>(crypto);
    f.gp->setSessionStore(f.store.get());
    f.gp->setSendSealedFn(
        [&f](const std::string& peer, const nlohmann::json& payload) {
            f.captured.push_back({peer, payload});
        });
    return f;
}

TEST_F(GroupProtocolSuite, Persist_OutboundChainSurvivesRestart) {
    auto f1 = makeFixture(*s_meCrypto);
    ASSERT_TRUE(f1.gp);

    // Before any send: persistence layer is empty.
    f1.gp->restorePersistedChains();
    EXPECT_EQ(f1.gp->outboundChainCount(), 0U);

    // Send two messages so the chain advances past idx 0.
    f1.gp->sendText("gid", "G", {s_meId, s_aliceId}, "one");
    f1.gp->sendText("gid", "G", {s_meId, s_aliceId}, "two");
    ASSERT_TRUE(f1.gp->hasMyChain("gid"));
    const uint64_t epochBefore = f1.gp->myEpoch("gid");

    // Capture the announce + msgs so we can verify post-restart that
    // the restored chain is byte-identical to the pre-restart one.
    nlohmann::json announceToAlice;
    std::vector<nlohmann::json> msgsToAlice;
    for (const auto& c : f1.captured) {
        if (c.peerId != s_aliceId) continue;
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce") announceToAlice = c.payload;
        else if (t == "group_msg")       msgsToAlice.push_back(c.payload);
    }
    ASSERT_EQ(msgsToAlice.size(), 2U);
    ASSERT_EQ(msgsToAlice[1]["skey_idx"].get<uint32_t>(), 1U);

    // Restart — tear down f1, reopen the same DB + store.
    const std::string dbPath  = f1.dbPath;
    const auto        dbKey   = f1.dbKey;
    const auto        skKey   = f1.storeKey;
    f1.gp.reset();
    f1.store.reset();
    f1.db.reset();

    auto f2 = reopenFixture(*s_meCrypto, dbPath, dbKey, skKey);
    ASSERT_TRUE(f2.gp);
    f2.gp->restorePersistedChains();

    // State preserved: chain present + epoch unchanged.
    EXPECT_TRUE(f2.gp->hasMyChain("gid"));
    EXPECT_EQ(f2.gp->myEpoch("gid"), epochBefore);

    // A third send after restart must carry skey_idx=2, not 0 — the
    // chain resumed where it left off.
    f2.captured.clear();
    f2.gp->sendText("gid", "G", {s_meId, s_aliceId}, "three");
    std::vector<nlohmann::json> post;
    for (const auto& c : f2.captured) {
        if (c.payload.value("type", std::string()) == "group_msg")
            post.push_back(c.payload);
    }
    ASSERT_EQ(post.size(), 1U);
    EXPECT_EQ(post[0]["skey_idx"].get<uint32_t>(), 2U)
        << "restored chain did not resume its idx counter";

    // Also verify no fresh skey_announce was fanned out on the post-
    // restart send (chain was already established).
    int postAnnounces = 0;
    for (const auto& c : f2.captured) {
        if (c.payload.value("type", std::string()) == "group_skey_announce")
            ++postAnnounces;
    }
    EXPECT_EQ(postAnnounces, 0);

    // Cross-check: Alice, installed with the ORIGINAL announce's seed,
    // decrypts the post-restart message successfully using her own
    // independently-maintained chain that never knew about the restart.
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.installRemoteChain("gid", s_meId,
        announceToAlice["epoch"].get<uint64_t>(),
        CryptoEngine::fromBase64Url(
            announceToAlice["seed"].get<std::string>()));
    Bytes pt = aliceGp.decryptGroupMessage("group_msg", "gid", s_meId,
        post[0]["skey_epoch"].get<uint64_t>(),
        post[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(post[0]["ciphertext"].get<std::string>()));
    ASSERT_FALSE(pt.empty());
    auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
    EXPECT_EQ(inner.value("text", std::string()), "three");

    // Clean up.
    std::error_code ec;
    std::filesystem::remove(dbPath, ec);
}

TEST_F(GroupProtocolSuite, Persist_InboundChainSurvivesRestart) {
    auto f1 = makeFixture(*s_meCrypto);
    f1.gp->restorePersistedChains();

    // Install alice's chain at a known seed.
    const Bytes seed(32, 0xA1);
    f1.gp->installRemoteChain("gid", s_aliceId, 3, seed);
    EXPECT_EQ(f1.gp->inboundChainCount(), 1U);

    // Restart.
    const std::string dbPath = f1.dbPath;
    const auto dbKey = f1.dbKey, skKey = f1.storeKey;
    f1.gp.reset(); f1.store.reset(); f1.db.reset();

    auto f2 = reopenFixture(*s_meCrypto, dbPath, dbKey, skKey);
    f2.gp->restorePersistedChains();

    EXPECT_EQ(f2.gp->inboundChainCount(), 1U);

    // Decrypt a fresh message from alice's matching chain — both
    // sides must derive the same key at idx=0.  AAD layout mirrors
    // GroupProtocol::buildGroupAad:
    //   msgType || '\n' || fromId || '\n' || gid || epoch(LE64) || idx(LE32)
    SenderChain aliceChain = SenderChain::fromSeed(seed);
    auto [idx, aliceKey] = aliceChain.next();

    const std::string gid     = "gid";
    const std::string msgType = "group_msg";
    const Bytes aad = [&]{
        Bytes a;
        a.insert(a.end(), msgType.begin(), msgType.end());
        a.push_back('\n');
        a.insert(a.end(), s_aliceId.begin(), s_aliceId.end());
        a.push_back('\n');
        a.insert(a.end(), gid.begin(), gid.end());
        for (int i = 0; i < 8; ++i) a.push_back((uint8_t)((3ULL >> (8*i)) & 0xFF));
        for (int i = 0; i < 4; ++i) a.push_back((uint8_t)((idx >> (8*i)) & 0xFF));
        return a;
    }();
    CryptoEngine helper;
    const Bytes pt_src = {'h','i'};
    const Bytes ct = helper.aeadEncrypt(aliceKey, pt_src, aad);

    Bytes pt = f2.gp->decryptGroupMessage(msgType, gid, s_aliceId, 3, idx, ct);
    ASSERT_FALSE(pt.empty());
    EXPECT_EQ(pt, pt_src);

    std::error_code ec;
    std::filesystem::remove(dbPath, ec);
}

TEST_F(GroupProtocolSuite, Persist_ForgetRemoteChainDeletesFromStore) {
    auto f1 = makeFixture(*s_meCrypto);
    f1.gp->restorePersistedChains();

    f1.gp->installRemoteChain("gid", s_aliceId, 0, Bytes(32, 0xA2));
    EXPECT_EQ(f1.gp->inboundChainCount(), 1U);

    f1.gp->forgetRemoteChain("gid", s_aliceId);
    EXPECT_EQ(f1.gp->inboundChainCount(), 0U);

    // Restart and verify the row is gone on disk too.
    const std::string dbPath = f1.dbPath;
    const auto dbKey = f1.dbKey, skKey = f1.storeKey;
    f1.gp.reset(); f1.store.reset(); f1.db.reset();

    auto f2 = reopenFixture(*s_meCrypto, dbPath, dbKey, skKey);
    f2.gp->restorePersistedChains();
    EXPECT_EQ(f2.gp->inboundChainCount(), 0U);

    std::error_code ec;
    std::filesystem::remove(dbPath, ec);
}

TEST_F(GroupProtocolSuite, Persist_RotationBumpsStoredEpoch) {
    auto f1 = makeFixture(*s_meCrypto);
    f1.gp->restorePersistedChains();

    f1.gp->sendText("gid", "G", {s_meId, s_aliceId, s_bobId}, "pre-rotate");
    f1.gp->setKnownMembers("gid", {s_meId, s_aliceId, s_bobId});
    ASSERT_EQ(f1.gp->myEpoch("gid"), 0U);

    // Remove bob — triggers rotation + persist.
    f1.gp->sendMemberUpdate("gid", "G", {s_meId, s_aliceId});
    ASSERT_EQ(f1.gp->myEpoch("gid"), 1U);

    // Restart — restored epoch must reflect the rotation, not the
    // pre-rotation state.
    const std::string dbPath = f1.dbPath;
    const auto dbKey = f1.dbKey, skKey = f1.storeKey;
    f1.gp.reset(); f1.store.reset(); f1.db.reset();

    auto f2 = reopenFixture(*s_meCrypto, dbPath, dbKey, skKey);
    f2.gp->restorePersistedChains();
    EXPECT_TRUE(f2.gp->hasMyChain("gid"));
    EXPECT_EQ(f2.gp->myEpoch("gid"), 1U);

    std::error_code ec;
    std::filesystem::remove(dbPath, ec);
}

TEST_F(GroupProtocolSuite, Persist_NoStoreMeansInMemoryOnly) {
    // Sanity: a GroupProtocol without a SessionStore wired behaves
    // exactly as before — state lives in memory only and vanishes on
    // destruction.  Guards against regressions that accidentally
    // require a store for basic operation.
    GroupProtocol gp(*s_meCrypto);
    std::vector<CapturedSend> cap;
    gp.setSendSealedFn(
        [&](const std::string& p, const nlohmann::json& pl) {
            cap.push_back({p, pl});
        });
    // No setSessionStore call.
    gp.restorePersistedChains();   // no-op without a store

    gp.sendText("gid", "G", {s_meId, s_aliceId}, "hi");
    EXPECT_TRUE(gp.hasMyChain("gid"));
}
