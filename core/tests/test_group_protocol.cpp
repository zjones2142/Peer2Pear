// test_group_protocol.cpp — tests for GroupProtocol.
//
// GroupProtocol owns:
//   1. Outbound send methods (text / leave / rename / avatar / member_update)
//      that fan out through a SendSealedFn callback per member.
//   2. The roster authorization gate isAuthorizedSender — with
//      deny-by-default for unknown groups and bootstrap-on-first-
//      trusted-message semantics via upsertMembersFromTrustedMessage.
//   3. Per-group outbound seq counters + per-(group, sender) inbound
//      monotonic guard via recordInboundSeq.
//
// None of this requires a live session.  We give the protocol a mock
// SendSealedFn that captures every fan-out call, then assert the payload
// shape, recipient list, seq numbering, and roster state.

#include "GroupProtocol.hpp"

#include "AppDataStore.hpp"
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

Bytes randomKey32() {
    Bytes k(32);
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
            [this](const std::string& peer, const nlohmann::json& payload) -> Bytes {
                m_captured.push_back({peer, payload});
                return {};
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

// ── 1. Roster authorization ──────────────────────────────────────────────────

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
    // is the known first-mover race; we defend by only accepting a list
    // that the claimed sender is actually in.
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
    EXPECT_EQ(first["type"],    "group_msg");
    EXPECT_EQ(first["groupId"], "gid");
    EXPECT_EQ(first["from"],    s_meId);
    EXPECT_EQ(first["skey_epoch"].get<uint64_t>(), 0U);
    EXPECT_EQ(first["skey_idx"].get<uint32_t>(), 0U);
    EXPECT_FALSE(first.contains("text"))      << "plaintext leaked into group_msg";
    EXPECT_FALSE(first.contains("seq"))       << "seq should not be present on group_msg";
    // Arch-review #3: groupName + members live inside the ciphertext,
    // not on the outer envelope.  A 1:1 ratchet peek no longer leaks
    // the group's roster or display name.
    EXPECT_FALSE(first.contains("groupName")) << "plaintext groupName leaked";
    EXPECT_FALSE(first.contains("members"))   << "plaintext members leaked";
    ASSERT_TRUE(first.contains("ciphertext"));
    EXPECT_FALSE(first["ciphertext"].get<std::string>().empty());

    for (const auto& m : msgs) {
        EXPECT_EQ(m["msgId"],      first["msgId"]);
        EXPECT_EQ(m["ts"],         first["ts"]);
        EXPECT_EQ(m["ciphertext"], first["ciphertext"]);
        EXPECT_EQ(m["skey_idx"],   first["skey_idx"]);
        EXPECT_EQ(m["skey_epoch"], first["skey_epoch"]);
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

TEST_F(GroupProtocolSuite, SendLeave_EncryptsGroupNameAndMembers) {
    // groupName + members must NOT ride on the outer envelope.  They
    // live inside the sender-chain ciphertext so a relay operator
    // can't harvest "alice left group X with members B,C,D" as
    // plaintext metadata.
    m_gp->sendLeave("gid", "My Group", {s_meId, s_aliceId, s_bobId});

    auto leaves = capturedOfType("group_leave");
    ASSERT_EQ(leaves.size(), 2U);
    EXPECT_EQ(countTo(s_meId), 0);

    // Lazy chain creation also fans skey_announce to each non-self
    // member, same as sendRename / sendAvatar.
    EXPECT_EQ(countTypeTo("group_skey_announce", s_aliceId), 1);
    EXPECT_EQ(countTypeTo("group_skey_announce", s_bobId),   1);

    for (const auto& l : leaves) {
        EXPECT_EQ(l["type"],    "group_leave");
        EXPECT_EQ(l["groupId"], "gid");
        EXPECT_EQ(l["from"],    s_meId);
        EXPECT_FALSE(l.contains("members"))
            << "plaintext members leaked";
        EXPECT_FALSE(l.contains("groupName"))
            << "plaintext groupName leaked";
        ASSERT_TRUE(l.contains("ciphertext"));
        EXPECT_FALSE(l["ciphertext"].get<std::string>().empty());
    }
    // Every fan-out shares the same msgId + ciphertext (one logical action).
    EXPECT_EQ(leaves[0]["msgId"],      leaves[1]["msgId"]);
    EXPECT_EQ(leaves[0]["ciphertext"], leaves[1]["ciphertext"]);
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

TEST_F(GroupProtocolSuite, InstallRemoteChain_RejectsEpochDowngrade) {
    // An attacker who captured a previous epoch's seed (e.g., from a
    // compromised member's disk or a stale relay log) could replay
    // group_skey_announce at epoch N-1 after the group rotated to
    // epoch N.  Without the downgrade guard, the receiver would
    // overwrite the current chain with the stale seed — downgrading
    // the group back to a known-compromised epoch.  This test pins
    // the rejection.

    // 1. Sender (m_gp) emits a real epoch-0 skey + msg.
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "hello-epoch0");
    auto announces0 = capturedOfType("group_skey_announce");
    auto msgs0      = capturedOfType("group_msg");
    ASSERT_EQ(announces0.size(), 1U);
    ASSERT_EQ(msgs0.size(),      1U);
    const uint64_t epoch0 = announces0[0]["epoch"].get<uint64_t>();

    GroupProtocol receiver(*s_aliceCrypto);
    receiver.installRemoteChain("gid", s_meId, epoch0,
        CryptoEngine::fromBase64Url(announces0[0]["seed"].get<std::string>()));

    // Sanity: epoch-0 message decrypts.
    Bytes pt0 = receiver.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs0[0]["skey_epoch"].get<uint64_t>(),
        msgs0[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msgs0[0]["ciphertext"].get<std::string>()));
    ASSERT_FALSE(pt0.empty());

    // 2. Sender genuinely rotates to epoch 1 + sends.
    m_captured.clear();
    m_gp->rotateMyChain("gid", {s_meId, s_aliceId});
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "hello-epoch1");
    auto announces1 = capturedOfType("group_skey_announce");
    auto msgs1      = capturedOfType("group_msg");
    ASSERT_EQ(announces1.size(), 1U);
    ASSERT_EQ(msgs1.size(),      1U);
    const uint64_t epoch1 = announces1[0]["epoch"].get<uint64_t>();
    ASSERT_GT(epoch1, epoch0);

    receiver.installRemoteChain("gid", s_meId, epoch1,
        CryptoEngine::fromBase64Url(announces1[0]["seed"].get<std::string>()));
    Bytes pt1 = receiver.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs1[0]["skey_epoch"].get<uint64_t>(),
        msgs1[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msgs1[0]["ciphertext"].get<std::string>()));
    ASSERT_FALSE(pt1.empty());

    // 3. Attacker re-injects epoch 0 with a seed they control.
    //    Pre-fix: this overwrites receiver's chain with attackerSeed,
    //    silently downgrading.  Post-fix: ignored.
    const Bytes attackerSeed(32, 0xCC);
    receiver.installRemoteChain("gid", s_meId, epoch0, attackerSeed);

    // 4. Proof: the sender's NEXT epoch-1 message must still decrypt.
    //    If the downgrade had taken effect, the receiver's chain would
    //    now be derived from attackerSeed (at epoch 0), and the new
    //    epoch-1 ciphertext would be undecryptable because the chain
    //    is at the wrong epoch + wrong seed.
    m_captured.clear();
    m_gp->sendText("gid", "G", {s_meId, s_aliceId}, "hello-epoch1-again");
    auto msgs1b = capturedOfType("group_msg");
    ASSERT_EQ(msgs1b.size(), 1U);
    Bytes pt1b = receiver.decryptGroupMessage("group_msg", "gid", s_meId,
        msgs1b[0]["skey_epoch"].get<uint64_t>(),
        msgs1b[0]["skey_idx"].get<uint32_t>(),
        CryptoEngine::fromBase64Url(msgs1b[0]["ciphertext"].get<std::string>()));
    EXPECT_FALSE(pt1b.empty()) << "downgrade attack overwrote the epoch-1 chain";
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
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
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
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
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
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
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

// Forward secrecy on the skipped-key window.  After a successful
// AEAD decrypt at idx=N the message key for N must be dropped from
// the chain's cache so a later in-memory or on-disk compromise
// cannot recover already-delivered keys.  Re-running the same
// decrypt after success therefore returns empty — the second call
// has nothing to look up.  AEAD failures don't trigger erasure
// (covered by `_ForgedCiphertextLeavesKeyForLegitimateRetry` below).
TEST_F(GroupProtocolSuite, DecryptGroupMessage_ErasesSkippedKeyAfterSuccess) {
    // Alice sends one message in a group containing me.
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
        });
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "once");

    nlohmann::json announce, msg;
    for (const auto& c : aliceCaptured) {
        if (c.peerId != s_meId) continue;
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

    const Bytes ct    = CryptoEngine::fromBase64Url(
        msg["ciphertext"].get<std::string>());
    const uint64_t ep = msg["skey_epoch"].get<uint64_t>();
    const uint32_t ix = msg["skey_idx"].get<uint32_t>();

    Bytes first = m_gp->decryptGroupMessage(
        "group_msg", "gid", s_aliceId, ep, ix, ct);
    ASSERT_FALSE(first.empty());

    // Second call on the same idx must return empty — the key was
    // erased from the skipped cache after the first successful AEAD
    // verify.  In production the envelope-id dedup at ChatController
    // catches retransmits before they reach this layer; the second
    // decrypt being impossible is a security property, not a
    // correctness regression.
    Bytes second = m_gp->decryptGroupMessage(
        "group_msg", "gid", s_aliceId, ep, ix, ct);
    EXPECT_TRUE(second.empty()) << "skipped key not erased after success";
}

// Companion to the above: a forged ciphertext at the same idx must
// NOT consume the key, so a legitimate retransmit can still decrypt.
TEST_F(GroupProtocolSuite, DecryptGroupMessage_ForgedCiphertextLeavesKeyForLegitimateRetry) {
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
        });
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "real");

    nlohmann::json announce, msg;
    for (const auto& c : aliceCaptured) {
        if (c.peerId != s_meId) continue;
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce") announce = c.payload;
        if (t == "group_msg")            msg      = c.payload;
    }
    m_gp->installRemoteChain("gid", s_aliceId,
                              announce["epoch"].get<uint64_t>(),
                              CryptoEngine::fromBase64Url(
                                  announce["seed"].get<std::string>()));

    Bytes goodCt = CryptoEngine::fromBase64Url(
        msg["ciphertext"].get<std::string>());
    Bytes badCt = goodCt;
    ASSERT_GT(badCt.size(), 25U);
    badCt[25] ^= 0x01;

    const uint64_t ep = msg["skey_epoch"].get<uint64_t>();
    const uint32_t ix = msg["skey_idx"].get<uint32_t>();

    // Forged ciphertext fails AEAD — must NOT erase the key.
    EXPECT_TRUE(m_gp->decryptGroupMessage(
        "group_msg", "gid", s_aliceId, ep, ix, badCt).empty());

    // Legitimate ciphertext at same idx still decrypts.
    Bytes pt = m_gp->decryptGroupMessage(
        "group_msg", "gid", s_aliceId, ep, ix, goodCt);
    ASSERT_FALSE(pt.empty());
    auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
    EXPECT_EQ(inner.value("text", std::string()), "real");
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
        [this](const std::string& p, const nlohmann::json& pl) -> Bytes {
            m_captured.push_back({p, pl});
            return {};
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
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
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
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
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

// With only one prev slot, a rapid 0->1->2 rekey would drop epoch
// 0's chain when epoch 2 arrived.  In-flight messages from epoch 0
// within the grace window then become undecryptable.  With the slot
// array at two, both prior epochs stay reachable across a double
// rotation.
TEST_F(GroupProtocolSuite, DecryptGroupMessage_RapidDoubleRekeyKeepsBothPrevEpochs) {
    std::vector<CapturedSend> aliceCaptured;
    GroupProtocol aliceGp(*s_aliceCrypto);
    aliceGp.setSendSealedFn(
        [&](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            aliceCaptured.push_back({peer, payload});
            return {};
        });

    // Alice sends one message at each of three epochs (0, 1, 2),
    // rotating between them — the back-to-back-rotation case.
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg @ 0");
    aliceGp.rotateMyChain("gid", {s_aliceId, s_meId});
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg @ 1");
    aliceGp.rotateMyChain("gid", {s_aliceId, s_meId});
    aliceGp.sendText("gid", "G", {s_aliceId, s_meId}, "msg @ 2");

    // Walk Alice's captured fan-out, picking out the per-epoch announce
    // and msg payloads addressed to me.  Order in the capture list is
    // deterministic (one outbound per call).
    nlohmann::json an[3], msg[3];
    int seenAnnounces = 0, seenMsgs = 0;
    for (const auto& c : aliceCaptured) {
        if (c.peerId != s_meId) continue;
        const std::string t = c.payload.value("type", std::string());
        if (t == "group_skey_announce" && seenAnnounces < 3)
            an[seenAnnounces++] = c.payload;
        else if (t == "group_msg" && seenMsgs < 3)
            msg[seenMsgs++] = c.payload;
    }
    ASSERT_EQ(seenAnnounces, 3);
    ASSERT_EQ(seenMsgs,      3);

    // Install all three chains in order — second install moves epoch 0
    // into prevSlots[0]; third install pushes it back to prevSlots[1].
    for (int i = 0; i < 3; ++i) {
        m_gp->installRemoteChain("gid", s_aliceId,
            an[i]["epoch"].get<uint64_t>(),
            CryptoEngine::fromBase64Url(an[i]["seed"].get<std::string>()));
    }

    // All three messages must decrypt within the (default) grace window.
    for (int i = 0; i < 3; ++i) {
        Bytes pt = m_gp->decryptGroupMessage("group_msg", "gid", s_aliceId,
            msg[i]["skey_epoch"].get<uint64_t>(),
            msg[i]["skey_idx"].get<uint32_t>(),
            CryptoEngine::fromBase64Url(msg[i]["ciphertext"].get<std::string>()));
        ASSERT_FALSE(pt.empty())
            << "epoch " << i << " unreachable after double rekey";
        auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
        EXPECT_EQ(inner.value("text", std::string()),
                  std::string("msg @ ") + char('0' + i));
    }
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
    Bytes             dbKey;
    Bytes             storeKey;
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
        [&f](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            f.captured.push_back({peer, payload});
            return {};
        });
    return f;
}

// Reopen an existing DB + re-wire a fresh GroupProtocol against it.
// Callers hand in the dbPath / dbKey / storeKey from makeFixture.
static PersistenceFixture reopenFixture(CryptoEngine& crypto,
                                          const std::string& dbPath,
                                          const Bytes& dbKey,
                                          const Bytes& storeKey) {
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
        [&f](const std::string& peer, const nlohmann::json& payload) -> Bytes {
            f.captured.push_back({peer, payload});
            return {};
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
        [&](const std::string& p, const nlohmann::json& pl) -> Bytes {
            cap.push_back({p, pl});
            return {};
        });
    // No setSessionStore call.
    gp.restorePersistedChains();   // no-op without a store

    gp.sendText("gid", "G", {s_meId, s_aliceId}, "hi");
    EXPECT_TRUE(gp.hasMyChain("gid"));
}

// ── pv=2 Causally-Linked Pairwise receiver state machine ───────────────────
//
// dispatchGroupMessageV2 owns the chain-state + buffer transitions on
// the receiver side.  These tests construct a GroupProtocol with a
// real AppDataStore (so chain_state / group_msg_buffer round-trip
// through SQLCipher) and exercise each transition in isolation:
//
//   - in-order delivery + chain advances
//   - prev_hash chain across consecutive messages
//   - out-of-order: buffered + blocked + gap range
//   - drain on gap fill (multi-step)
//   - replay drop (counter < expected)
//   - splice rejection (prev_hash mismatch)
//   - session reset surfaces lostMessages
//
// The sender path is exercised at integration level (test_e2e_two_clients)
// where a real handshake gives sessionIdFor() something to return.
// Here we synthesize fake sessionId / sealed envelope bytes — the
// receiver state machine doesn't decrypt; it only chains by hash.

namespace {

struct V2Env {
    std::string                   dir;
    std::unique_ptr<SqlCipherDb>  db;
    std::unique_ptr<AppDataStore> store;
    std::unique_ptr<GroupProtocol> gp;
};

V2Env makeV2Env(CryptoEngine& crypto) {
    V2Env e;
    e.dir = makeTempDir("p2p-gp-v2");
    e.db  = std::make_unique<SqlCipherDb>();
    EXPECT_TRUE(e.db->open(e.dir + "/test.db", randomKey32()));
    e.store = std::make_unique<AppDataStore>();
    EXPECT_TRUE(e.store->bind(*e.db));
    e.store->setEncryptionKey(randomKey32());
    e.gp = std::make_unique<GroupProtocol>(crypto);
    e.gp->setAppDataStore(e.store.get());
    return e;
}

Bytes makeSessionId(uint8_t marker) {
    return Bytes(8, marker);
}

// Synthesize a "sealed envelope" the receiver can hash — the hash is
// what flows into prev_hash; the bytes themselves are otherwise opaque.
Bytes makeSealedEnv(uint8_t marker, size_t pad = 64) {
    Bytes env;
    env.reserve(33 + pad);
    env.push_back(0x01);
    env.insert(env.end(), 32, marker);
    env.insert(env.end(), pad, marker);
    return env;
}

Bytes hashEnv(const Bytes& sealed) {
    Bytes h(16);
    crypto_generichash(h.data(), h.size(),
                        sealed.data(), sealed.size(), nullptr, 0);
    return h;
}

}  // namespace

TEST_F(GroupProtocolSuite, V2ReceiverDeliversFirstMessageInSession) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xA1);
    const Bytes s1  = makeSealedEnv(0xA1);

    // First message of the session: empty prev_hash is the convention.
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sid, /*ctr=*/1, /*prev=*/{},
        "hello", "Alice", 1234, "msg1", s1);

    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Delivered);
    ASSERT_EQ(r.deliver.size(), 1u);
    EXPECT_EQ(r.deliver[0].body,    "hello");
    EXPECT_EQ(r.deliver[0].counter, 1);
    EXPECT_EQ(r.deliver[0].msgId,   "msg1");
    EXPECT_FALSE(r.blocked);

    // Chain state should be persisted: expected_next = 2,
    // last_hash = hash(s1).
    AppDataStore::ChainState st;
    ASSERT_TRUE(e.store->loadChainState("g", s_aliceId, st));
    EXPECT_EQ(st.sessionId,    sid);
    EXPECT_EQ(st.expectedNext, 2);
    EXPECT_EQ(st.lastHash,     hashEnv(s1));
}

TEST_F(GroupProtocolSuite, V2ReceiverChainsPrevHashAcrossMessages) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xB2);
    const Bytes s1  = makeSealedEnv(0xB1);
    const Bytes s2  = makeSealedEnv(0xB2);

    e.gp->dispatchGroupMessageV2("g", s_aliceId, sid, 1, {}, "m1", "A", 1, "i1", s1);

    // Second message: prev_hash MUST equal hash(s1) for delivery.
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sid, 2, hashEnv(s1), "m2", "A", 2, "i2", s2);

    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Delivered);
    ASSERT_EQ(r.deliver.size(), 1u);
    EXPECT_EQ(r.deliver[0].body, "m2");

    AppDataStore::ChainState st;
    e.store->loadChainState("g", s_aliceId, st);
    EXPECT_EQ(st.expectedNext, 3);
    EXPECT_EQ(st.lastHash,     hashEnv(s2));
}

TEST_F(GroupProtocolSuite, V2ReceiverBuffersOutOfOrderAndMarksBlocked) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xC3);
    const Bytes s3  = makeSealedEnv(0xC3);

    // No prior state; ctr=3 arriving first is way ahead of expected=1.
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sid, 3, /*prev=*/Bytes(16, 0xDD),
        "third", "A", 3, "i3", s3);

    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Buffered);
    EXPECT_TRUE(r.blocked);
    EXPECT_EQ(r.gapFrom, 1);
    EXPECT_EQ(r.gapTo,   2);
    EXPECT_TRUE(r.deliver.empty());

    // chain_state.gap_from / gap_to should be persisted.
    AppDataStore::ChainState st;
    e.store->loadChainState("g", s_aliceId, st);
    EXPECT_EQ(st.expectedNext, 1) << "expectedNext stays at 1 until gap fills";
    EXPECT_EQ(st.gapFrom,      1);
    EXPECT_EQ(st.gapTo,        2);
    EXPECT_NE(st.blockedSince, 0);
}

TEST_F(GroupProtocolSuite, V2ReceiverDrainsBufferOnGapFill) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xD4);
    const Bytes s1  = makeSealedEnv(0xD1);
    const Bytes s2  = makeSealedEnv(0xD2);
    const Bytes s3  = makeSealedEnv(0xD3);

    // Out of order: 3 arrives, then 2, then 1.
    e.gp->dispatchGroupMessageV2("g", s_aliceId, sid, 3, hashEnv(s2), "m3", "A", 3, "i3", s3);
    e.gp->dispatchGroupMessageV2("g", s_aliceId, sid, 2, hashEnv(s1), "m2", "A", 2, "i2", s2);

    // Now ctr=1 arrives — should deliver itself + drain 2 + drain 3.
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sid, 1, /*prev=*/{}, "m1", "A", 1, "i1", s1);

    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Delivered);
    EXPECT_FALSE(r.blocked);
    ASSERT_EQ(r.deliver.size(), 3u);
    EXPECT_EQ(r.deliver[0].body, "m1");
    EXPECT_EQ(r.deliver[0].counter, 1);
    EXPECT_EQ(r.deliver[1].body, "m2");
    EXPECT_EQ(r.deliver[1].counter, 2);
    EXPECT_EQ(r.deliver[2].body, "m3");
    EXPECT_EQ(r.deliver[2].counter, 3);

    AppDataStore::ChainState st;
    e.store->loadChainState("g", s_aliceId, st);
    EXPECT_EQ(st.expectedNext,  4);
    EXPECT_EQ(st.lastHash,      hashEnv(s3));
    EXPECT_EQ(st.blockedSince,  0) << "blocked cleared once buffer empties";
}

TEST_F(GroupProtocolSuite, V2ReceiverDropsReplay) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xE5);
    const Bytes s1  = makeSealedEnv(0xE1);

    e.gp->dispatchGroupMessageV2("g", s_aliceId, sid, 1, {}, "m1", "A", 1, "i1", s1);

    // Re-receive ctr=1 → silent drop, deliver list empty.
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sid, 1, {}, "m1", "A", 1, "i1", s1);

    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Dropped);
    EXPECT_TRUE(r.deliver.empty());
}

TEST_F(GroupProtocolSuite, V2ReceiverRejectsSpliceOnPrevHashMismatch) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xF6);
    const Bytes s1  = makeSealedEnv(0xF1);
    const Bytes s2  = makeSealedEnv(0xF2);

    e.gp->dispatchGroupMessageV2("g", s_aliceId, sid, 1, {}, "m1", "A", 1, "i1", s1);

    // ctr=2 arrives with the WRONG prev_hash (forged).  Receiver must
    // drop without advancing the chain — defends against splice attacks.
    Bytes wrongPrev(16, 0xFF);
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sid, 2, wrongPrev, "spliced", "A", 2, "i2", s2);

    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Dropped);
    EXPECT_TRUE(r.deliver.empty());

    // Chain state should NOT have advanced.
    AppDataStore::ChainState st;
    e.store->loadChainState("g", s_aliceId, st);
    EXPECT_EQ(st.expectedNext, 2) << "still expecting 2 — splice did not advance the chain";
    EXPECT_EQ(st.lastHash,     hashEnv(s1));
}

TEST_F(GroupProtocolSuite, V2ReceiverSessionResetSurfacesLostMessages) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sidOld = makeSessionId(0x10);
    const Bytes sidNew = makeSessionId(0x20);

    // Buffer two messages on the OLD session — the gap never fills.
    e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sidOld, 5, Bytes(16, 0xAA),
        "old5", "A", 1, "io5", makeSealedEnv(0xAA));
    e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sidOld, 6, Bytes(16, 0xBB),
        "old6", "A", 2, "io6", makeSealedEnv(0xBB));

    // Sender's session reset (e.g., they wiped + re-handshook).  We
    // see ctr=1 on a NEW session_id.
    const Bytes sNew1 = makeSealedEnv(0xCC);
    auto r = e.gp->dispatchGroupMessageV2(
        "g", s_aliceId, sidNew, 1, /*prev=*/{},
        "fresh", "A", 100, "ifresh", sNew1);

    // Old buffer drained as "lost"; fresh delivered.
    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::SessionReset);
    EXPECT_EQ(r.lostMessages, 2);
    ASSERT_EQ(r.deliver.size(), 1u);
    EXPECT_EQ(r.deliver[0].body, "fresh");

    AppDataStore::ChainState st;
    e.store->loadChainState("g", s_aliceId, st);
    EXPECT_EQ(st.sessionId,    sidNew);
    EXPECT_EQ(st.expectedNext, 2);
    EXPECT_EQ(st.lastHash,     hashEnv(sNew1));
}

TEST_F(GroupProtocolSuite, V2ReceiverNoOpWithoutAppDataStore) {
    GroupProtocol gp(*s_meCrypto);  // no setAppDataStore

    auto r = gp.dispatchGroupMessageV2(
        "g", s_aliceId, makeSessionId(0x99), 1, {},
        "x", "A", 0, "i", makeSealedEnv(0x99));
    EXPECT_EQ(r.status, GroupProtocol::ReceiveStatus::Dropped);
}

// ── gap_request: receiver→sender, sender replays from cache ────────────

TEST_F(GroupProtocolSuite, V2GapRequestSendsCorrectPayloadShape) {
    auto e = makeV2Env(*s_meCrypto);
    std::vector<CapturedSend> cap;
    e.gp->setSendSealedFn([&](const std::string& peer,
                                const nlohmann::json& payload) -> Bytes {
        cap.push_back({peer, payload});
        return {};
    });

    const Bytes sid = makeSessionId(0xA1);
    e.gp->sendGapRequest(s_aliceId, "g", sid, /*from=*/3, /*to=*/7);

    ASSERT_EQ(cap.size(), 1u);
    EXPECT_EQ(cap[0].peerId, s_aliceId);
    EXPECT_EQ(cap[0].payload.value("type",     std::string()),
              "group_gap_request");
    EXPECT_EQ(cap[0].payload.value("from",     std::string()), s_meId);
    EXPECT_EQ(cap[0].payload.value("groupId",  std::string()), "g");
    EXPECT_EQ(cap[0].payload.value("session",  std::string()),
              CryptoEngine::toBase64Url(sid));
    EXPECT_EQ(cap[0].payload.value("from_ctr", int64_t{0}), 3);
    EXPECT_EQ(cap[0].payload.value("to_ctr",   int64_t{0}), 7);
    EXPECT_FALSE(cap[0].payload.value("msgId", std::string()).empty());
}

TEST_F(GroupProtocolSuite, V2GapRequestDropsInvalidArgs) {
    auto e = makeV2Env(*s_meCrypto);
    std::vector<CapturedSend> cap;
    e.gp->setSendSealedFn([&](const std::string& p,
                                const nlohmann::json& pl) -> Bytes {
        cap.push_back({p, pl});
        return {};
    });

    const Bytes sid = makeSessionId(0xB1);
    // Empty target peer.
    e.gp->sendGapRequest("", "g", sid, 1, 1);
    // Empty group.
    e.gp->sendGapRequest(s_aliceId, "", sid, 1, 1);
    // Empty session.
    e.gp->sendGapRequest(s_aliceId, "g", {}, 1, 1);
    // Inverted range.
    e.gp->sendGapRequest(s_aliceId, "g", sid, 5, 2);
    // Zero/negative counter.
    e.gp->sendGapRequest(s_aliceId, "g", sid, 0, 1);

    EXPECT_TRUE(cap.empty()) << "every malformed call must short-circuit";
}

TEST_F(GroupProtocolSuite, V2HandleGapRequestReplaysCachedRange) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xC1);

    // Pre-populate replay cache with five sealed envelopes for Alice.
    Bytes envs[5];
    for (int i = 0; i < 5; ++i) {
        envs[i] = makeSealedEnv(0xC0 + i);
        e.store->addReplayCacheEntry(s_aliceId, "g", sid, /*ctr=*/i + 1,
                                       envs[i], /*sentAt=*/1000 + i);
    }

    // Wire the raw-relay callback to capture replays.
    std::vector<Bytes> replayed;
    e.gp->setReplayRelayFn([&](const Bytes& b) { replayed.push_back(b); });

    // Alice asks us for ctr=2..4 — we should replay 3 envelopes
    // (byte-identical to what we cached) in counter order.
    e.gp->handleGapRequest(s_aliceId, "g", sid, 2, 4);

    ASSERT_EQ(replayed.size(), 3u);
    EXPECT_EQ(replayed[0], envs[1]);  // ctr=2
    EXPECT_EQ(replayed[1], envs[2]);  // ctr=3
    EXPECT_EQ(replayed[2], envs[3]);  // ctr=4
}

TEST_F(GroupProtocolSuite, V2HandleGapRequestSkipsMissingCounters) {
    auto e = makeV2Env(*s_meCrypto);
    const Bytes sid = makeSessionId(0xD1);

    // Cache only ctr=2 and ctr=4.  Range [1..5] should replay just
    // those two — TTL-expired or never-sent counters silently skip.
    Bytes env2 = makeSealedEnv(0xD2);
    Bytes env4 = makeSealedEnv(0xD4);
    e.store->addReplayCacheEntry(s_aliceId, "g", sid, 2, env2, 1000);
    e.store->addReplayCacheEntry(s_aliceId, "g", sid, 4, env4, 1000);

    std::vector<Bytes> replayed;
    e.gp->setReplayRelayFn([&](const Bytes& b) { replayed.push_back(b); });

    e.gp->handleGapRequest(s_aliceId, "g", sid, 1, 5);

    ASSERT_EQ(replayed.size(), 2u);
    EXPECT_EQ(replayed[0], env2);
    EXPECT_EQ(replayed[1], env4);
}

TEST_F(GroupProtocolSuite, V2HandleGapRequestNoOpWithoutDeps) {
    GroupProtocol gp(*s_meCrypto);  // no AppDataStore, no replay relay
    // Should not crash; should silently no-op.
    gp.handleGapRequest(s_aliceId, "g", makeSessionId(0xE1), 1, 5);

    // Even with AppDataStore but no replay relay, no-op.
    auto e = makeV2Env(*s_meCrypto);
    e.gp->handleGapRequest(s_aliceId, "g", makeSessionId(0xE1), 1, 5);
    // No assertion — verifying it didn't crash is enough.
}

TEST_F(GroupProtocolSuite, V2GapRequestRoundTripAcrossPeers) {
    // End-to-end: A pre-fills its replay cache, B sends a gap request,
    // A handles it and B sees the replayed envelopes back in raw form.
    auto a = makeV2Env(*s_aliceCrypto);
    auto b = makeV2Env(*s_bobCrypto);

    const Bytes sid = makeSessionId(0xF1);

    // Alice sent three messages to Bob; cache the sealed bytes.
    Bytes env1 = makeSealedEnv(0xF1);
    Bytes env2 = makeSealedEnv(0xF2);
    Bytes env3 = makeSealedEnv(0xF3);
    a.store->addReplayCacheEntry(s_bobId, "g", sid, 1, env1, 1000);
    a.store->addReplayCacheEntry(s_bobId, "g", sid, 2, env2, 1001);
    a.store->addReplayCacheEntry(s_bobId, "g", sid, 3, env3, 1002);

    // Bob fires sendGapRequest, which goes through Alice's sendSealed.
    // We capture Bob's request and route it manually to Alice's handler
    // (skipping the actual seal/unseal — those are SessionSealer's job).
    std::vector<CapturedSend> bobOut;
    b.gp->setSendSealedFn([&](const std::string& peer,
                                const nlohmann::json& payload) -> Bytes {
        bobOut.push_back({peer, payload});
        return {};
    });

    std::vector<Bytes> aliceReplayed;
    a.gp->setReplayRelayFn([&](const Bytes& env) {
        aliceReplayed.push_back(env);
    });

    b.gp->sendGapRequest(s_aliceId, "g", sid, /*from=*/1, /*to=*/3);

    // Bob's request landed at Alice's peer.
    ASSERT_EQ(bobOut.size(), 1u);
    EXPECT_EQ(bobOut[0].peerId, s_aliceId);

    // Alice processes the request — replays all three.
    a.gp->handleGapRequest(
        s_bobId, "g", sid,
        bobOut[0].payload.value("from_ctr", int64_t{0}),
        bobOut[0].payload.value("to_ctr",   int64_t{0}));

    ASSERT_EQ(aliceReplayed.size(), 3u);
    EXPECT_EQ(aliceReplayed[0], env1);
    EXPECT_EQ(aliceReplayed[1], env2);
    EXPECT_EQ(aliceReplayed[2], env3);
}
