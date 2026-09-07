// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Test } from "forge-std/Test.sol";
import { IValidatorManager } from "./IValidatorManager.sol";
import { ValidatorManager } from "./ValidatorManager.sol";

contract ValidatorManagerTest is Test {
    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);
    event ValidatorQuorumSet(uint8 quorum);
    event ValidatorNonceInvalidated(address indexed validator, bytes32 nonce);

    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    uint256 internal constant CAROL_PK = 0xCA201;
    uint256 internal constant DAVE_PK = 0xDA1E;

    ValidatorManager internal manager;
    address internal alice;
    address internal bob;
    address internal carol;
    address internal dave;

    function setUp() public {
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        carol = vm.addr(CAROL_PK);
        dave = vm.addr(DAVE_PK);

        address[] memory initial = new address[](3);
        initial[0] = alice;
        initial[1] = bob;
        initial[2] = carol;
        manager = new ValidatorManager(initial, 2);
    }

    function test_ConstructorInitializesState() public view {
        assertTrue(manager.isValidator(alice));
        assertTrue(manager.isValidator(bob));
        assertTrue(manager.isValidator(carol));
        assertFalse(manager.isValidator(dave));
        assertEq(manager.getValidatorCount(), 3);
        assertEq(manager.getValidatorQuorum(), 2);
    }

    function test_ConstructorRejectsEmptySet() public {
        address[] memory initial = new address[](0);
        vm.expectRevert(IValidatorManager.InvalidValidatorCount.selector);
        new ValidatorManager(initial, 1);
    }

    function test_ConstructorRejectsSingleValidator() public {
        address[] memory initial = new address[](1);
        initial[0] = alice;
        vm.expectRevert(IValidatorManager.InvalidValidatorCount.selector);
        new ValidatorManager(initial, 1);
    }

    function test_ConstructorRejectsZeroAddress() public {
        address[] memory initial = new address[](2);
        initial[0] = address(0);
        initial[1] = bob;
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.InvalidValidatorAddress.selector, address(0)));
        new ValidatorManager(initial, 1);
    }

    function test_ConstructorRejectsDuplicate() public {
        address[] memory initial = new address[](2);
        initial[0] = alice;
        initial[1] = alice;
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.ValidatorAlreadyAdded.selector, alice));
        new ValidatorManager(initial, 1);
    }

    function test_ConstructorRejectsQuorumZero() public {
        address[] memory initial = _twoValidators();
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        new ValidatorManager(initial, 0);
    }

    function test_ConstructorRejectsUnanimousQuorum() public {
        address[] memory initial = _twoValidators();
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        new ValidatorManager(initial, 2);
    }

    function test_ConstructorRejectsQuorumAboveCount() public {
        address[] memory initial = _twoValidators();
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        new ValidatorManager(initial, 3);
    }

    function test_ConstructorRejectsTooManyValidators() public {
        address[] memory initial = new address[](256);
        for (uint256 i = 0; i < 256; i++) {
            initial[i] = address(uint160(i + 1));
        }
        vm.expectRevert(IValidatorManager.InvalidValidatorCount.selector);
        new ValidatorManager(initial, 1);
    }

    function test_AssertValidatorSignaturesAcceptsQuorum() public view {
        bytes32 digest = keccak256("attestation");
        _assertSignatures(digest, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function test_AssertValidatorSignaturesRejectsBadLength() public {
        bytes32 digest = keccak256("attestation");
        vm.expectRevert(IValidatorManager.InvalidSignatureLength.selector);
        _assertSignatures(digest, hex"11");
    }

    function test_AssertValidatorSignaturesRejectsBelowQuorum() public {
        bytes32 digest = keccak256("attestation");
        bytes memory signatures = _sign(ALICE_PK, digest);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.InvalidValidatorSignatureCount.selector, 1, 2, 3));
        _assertSignatures(digest, signatures);
    }

    function test_AssertValidatorSignaturesRejectsAboveCount() public {
        bytes32 digest = keccak256("attestation");
        uint256[] memory pks = new uint256[](4);
        pks[0] = ALICE_PK;
        pks[1] = BOB_PK;
        pks[2] = CAROL_PK;
        pks[3] = DAVE_PK;
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.InvalidValidatorSignatureCount.selector, 4, 2, 3));
        _assertSignatures(digest, _signSorted(digest, pks));
    }

    function test_AssertValidatorSignaturesRejectsNonValidator() public {
        bytes32 digest = keccak256("attestation");
        bytes memory signatures = _signSorted(digest, _pks(ALICE_PK, DAVE_PK));
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.AddressNotValidator.selector, dave));
        _assertSignatures(digest, signatures);
    }

    function test_AssertValidatorSignaturesRejectsUnsorted() public {
        bytes32 digest = keccak256("attestation");
        address first = alice < bob ? alice : bob;
        uint256 highPk = first == alice ? BOB_PK : ALICE_PK;
        uint256 lowPk = first == alice ? ALICE_PK : BOB_PK;
        bytes memory signatures = bytes.concat(_sign(highPk, digest), _sign(lowPk, digest));
        vm.expectRevert(IValidatorManager.InvalidSignatureOrdering.selector);
        _assertSignatures(digest, signatures);
    }

    function test_AssertValidatorSignaturesRejectsDuplicateSigner() public {
        bytes32 digest = keccak256("attestation");
        bytes memory signatures = bytes.concat(_sign(ALICE_PK, digest), _sign(ALICE_PK, digest));
        vm.expectRevert(IValidatorManager.InvalidSignatureOrdering.selector);
        _assertSignatures(digest, signatures);
    }

    function test_ChangeValidatorAddsAndEmits() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);

        vm.expectEmit(true, false, false, true, address(manager));
        emit ValidatorAdded(dave);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(DAVE_PK, digest));

        assertTrue(manager.isValidator(dave));
        assertEq(manager.getValidatorCount(), 4);
        assertTrue(manager.usedNonces(alice, request.nonce));
        assertTrue(manager.usedNonces(bob, request.nonce));
    }

    function test_ChangeValidatorAddRejectsMissingSubjectSignature() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(IValidatorManager.InvalidSignatureLength.selector);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), bytes(""));
    }

    function test_ChangeValidatorAddRejectsWrongSubjectSigner() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(IValidatorManager.InvalidSubjectSignature.selector);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(ALICE_PK, digest));
    }

    function test_ChangeValidatorAddRejectsSubjectInQuorumBlob() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);
        bytes memory signatures = _signSorted(digest, _pks(ALICE_PK, DAVE_PK));
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.AddressNotValidator.selector, dave));
        manager.changeValidator(request, signatures, _sign(DAVE_PK, digest));
    }

    function test_ChangeValidatorAddRejectsAlreadyValidator() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(alice, _nonce("add-alice"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.ValidatorAlreadyAdded.selector, alice));
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(ALICE_PK, digest));
    }

    function test_ChangeValidatorAddRejectsMaxValidators() public {
        address[] memory initial = new address[](255);
        for (uint256 i = 0; i < 255; i++) {
            initial[i] = vm.addr(i + 1);
        }
        ValidatorManager full = new ValidatorManager(initial, 1);
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(address(full), request);
        vm.expectRevert(IValidatorManager.InvalidValidatorCount.selector);
        full.changeValidator(request, _sign(1, digest), _sign(DAVE_PK, digest));
    }

    function test_ChangeValidatorAddRejectsZeroAddress() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(address(0), _nonce("add-zero"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(IValidatorManager.InvalidSubjectSignature.selector);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(DAVE_PK, digest));
    }

    function test_ChangeValidatorRemoveWithoutDepartingSigner() public {
        _setQuorum(1);
        IValidatorManager.ChangeValidatorRequest memory request = _removeRequest(carol, _nonce("remove-carol"));
        bytes32 digest = _hashValidator(request);

        vm.expectEmit(true, false, false, true, address(manager));
        emit ValidatorRemoved(carol);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), bytes(""));

        assertFalse(manager.isValidator(carol));
        assertEq(manager.getValidatorCount(), 2);
    }

    function test_ChangeValidatorRemoveRejectsDepartingSubjectSignature() public {
        _setQuorum(1);
        IValidatorManager.ChangeValidatorRequest memory request = _removeRequest(carol, _nonce("remove-carol"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(IValidatorManager.InvalidSubjectSignature.selector);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(CAROL_PK, digest));
    }

    function test_ChangeValidatorRemoveRejectsUnknownValidator() public {
        IValidatorManager.ChangeValidatorRequest memory request = _removeRequest(dave, _nonce("remove-dave"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.ValidatorNotAdded.selector, dave));
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), bytes(""));
    }

    function test_ChangeValidatorRemoveRejectsUnanimousRemainder() public {
        IValidatorManager.ChangeValidatorRequest memory request = _removeRequest(carol, _nonce("remove-carol-unanimous"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(IValidatorManager.InvalidValidatorCount.selector);
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), bytes(""));
    }

    function test_ChangeValidatorRemoveRejectsBelowMinimum() public {
        _setQuorum(1);
        _remove(carol, _nonce("remove-carol"), _pks(ALICE_PK, BOB_PK));

        IValidatorManager.ChangeValidatorRequest memory request = _removeRequest(bob, _nonce("remove-bob"));
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(IValidatorManager.InvalidValidatorCount.selector);
        manager.changeValidator(request, _sign(ALICE_PK, digest), bytes(""));
    }

    function test_ChangeValidatorRejectsExpiredRequest() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        request.expiry = block.timestamp;
        vm.warp(block.timestamp + 1);
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.RequestExpired.selector, request.expiry, block.timestamp));
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(DAVE_PK, digest));
    }

    function test_ChangeValidatorRejectsReplay() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);
        bytes memory signatures = _signSorted(digest, _pks(ALICE_PK, BOB_PK));
        bytes memory subject = _sign(DAVE_PK, digest);
        manager.changeValidator(request, signatures, subject);

        address firstSigner = alice < bob ? alice : bob;
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.SignatureInvalidated.selector, firstSigner, request.nonce));
        manager.changeValidator(request, signatures, subject);
    }

    function test_ChangeValidatorRejectsWrongDigest() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);
        IValidatorManager.ChangeValidatorRequest memory other = request;
        other.expiry = request.expiry + 1;
        vm.expectRevert();
        manager.changeValidator(other, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(DAVE_PK, digest));
    }

    function test_ChangeValidatorQuorumSetsAndEmits() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(1, _nonce("quorum-1"));
        bytes32 digest = _hashQuorum(request);

        vm.expectEmit(false, false, false, true, address(manager));
        emit ValidatorQuorumSet(1);
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));

        assertEq(manager.getValidatorQuorum(), 1);
    }

    function test_ChangeValidatorQuorumCanRaise() public {
        _setQuorum(1);
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(2, _nonce("quorum-2"));
        bytes32 digest = _hashQuorum(request);
        manager.changeValidatorQuorum(request, _sign(ALICE_PK, digest));
        assertEq(manager.getValidatorQuorum(), 2);
    }

    function test_ChangeValidatorQuorumRejectsUnanimous() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(3, _nonce("quorum-3"));
        bytes32 digest = _hashQuorum(request);
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function test_ChangeValidatorQuorumRejectsZero() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(0, _nonce("quorum-0"));
        bytes32 digest = _hashQuorum(request);
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function test_ChangeValidatorQuorumRejectsUnchanged() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(2, _nonce("quorum-unchanged"));
        bytes32 digest = _hashQuorum(request);
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function test_ChangeValidatorQuorumRejectsExpired() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(1, _nonce("quorum-1"));
        request.expiry = block.timestamp;
        vm.warp(block.timestamp + 1);
        bytes32 digest = _hashQuorum(request);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.RequestExpired.selector, request.expiry, block.timestamp));
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function test_ChangeValidatorQuorumRejectsReplay() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(1, _nonce("quorum-1"));
        bytes32 digest = _hashQuorum(request);
        bytes memory signatures = _signSorted(digest, _pks(ALICE_PK, BOB_PK));
        manager.changeValidatorQuorum(request, signatures);
        address firstSigner = alice < bob ? alice : bob;
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.SignatureInvalidated.selector, firstSigner, request.nonce));
        manager.changeValidatorQuorum(request, signatures);
    }

    function test_InvalidateNonceRejectsThatSignerOnCurrentRequest() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        bytes32 digest = _hashValidator(request);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true, address(manager));
        emit ValidatorNonceInvalidated(alice, request.nonce);
        manager.invalidateNonce(request.nonce);

        assertTrue(manager.usedNonces(alice, request.nonce));
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.SignatureInvalidated.selector, alice, request.nonce));
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(DAVE_PK, digest));
    }

    function test_InvalidateNonceDoesNotBlockOtherSigners() public {
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        vm.prank(alice);
        manager.invalidateNonce(request.nonce);

        bytes32 digest = _hashValidator(request);
        manager.changeValidator(request, _signSorted(digest, _pks(BOB_PK, CAROL_PK)), _sign(DAVE_PK, digest));

        assertTrue(manager.isValidator(dave));
    }

    function test_InvalidateNonceRejectsNonValidator() public {
        vm.prank(dave);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.AddressNotValidator.selector, dave));
        manager.invalidateNonce(_nonce("unused"));
    }

    function test_InvalidateNonceRejectsSecondCallOnSameNonce() public {
        bytes32 requestNonce = _nonce("add-dave");
        vm.prank(alice);
        manager.invalidateNonce(requestNonce);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.NonceAlreadyInvalidated.selector, requestNonce));
        manager.invalidateNonce(requestNonce);
    }

    function test_InvalidateNonceDoesNotApplyToOtherNonces() public {
        vm.prank(alice);
        manager.invalidateNonce(_nonce("quorum-1"));

        IValidatorManager.ChangeValidatorQuorumRequest memory lower = _quorumRequest(1, _nonce("quorum-1"));
        bytes32 lowerDigest = _hashQuorum(lower);
        manager.changeValidatorQuorum(lower, _signSorted(lowerDigest, _pks(BOB_PK, CAROL_PK)));

        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(2, _nonce("quorum-2"));
        bytes32 digest = _hashQuorum(request);
        manager.changeValidatorQuorum(request, _sign(ALICE_PK, digest));
        assertEq(manager.getValidatorQuorum(), 2);
    }

    function test_InvalidateNonceAppliesToQuorumChange() public {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(1, _nonce("quorum-1"));
        bytes32 digest = _hashQuorum(request);
        vm.prank(bob);
        manager.invalidateNonce(request.nonce);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.SignatureInvalidated.selector, bob, request.nonce));
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function test_DistinctNoncesStayValidAfterAnotherRequest() public {
        IValidatorManager.ChangeValidatorRequest memory addRequest = _addRequest(dave, _nonce("add-dave"));
        bytes32 addDigest = _hashValidator(addRequest);
        bytes memory addSignatures = _signSorted(addDigest, _pks(ALICE_PK, BOB_PK));
        bytes memory subject = _sign(DAVE_PK, addDigest);

        _setQuorum(1);

        manager.changeValidator(addRequest, addSignatures, subject);
        assertTrue(manager.isValidator(dave));
    }

    function testFuzz_ConstructorValidQuorum(uint8 n, uint8 q) public {
        n = uint8(bound(n, 2, 20));
        q = uint8(bound(q, 1, n - 1));
        address[] memory initial = new address[](n);
        for (uint8 i = 0; i < n; i++) {
            initial[i] = vm.addr(uint256(i) + 1);
        }
        ValidatorManager deployed = new ValidatorManager(initial, q);
        assertEq(deployed.getValidatorCount(), n);
        assertEq(deployed.getValidatorQuorum(), q);
    }

    function testFuzz_ConstructorRejectsUnanimousOrZero(uint8 n, uint8 q) public {
        n = uint8(bound(n, 2, 20));
        q = uint8(bound(q, 0, 40));
        vm.assume(q == 0 || q >= n);
        address[] memory initial = new address[](n);
        for (uint8 i = 0; i < n; i++) {
            initial[i] = vm.addr(uint256(i) + 1);
        }
        vm.expectRevert(IValidatorManager.InvalidValidatorQuorum.selector);
        new ValidatorManager(initial, q);
    }

    function testFuzz_ExpiredChangeValidator(uint256 now_, uint256 expiry) public {
        now_ = bound(now_, 1, type(uint64).max);
        expiry = bound(expiry, 0, now_ - 1);
        vm.warp(now_);
        IValidatorManager.ChangeValidatorRequest memory request = _addRequest(dave, _nonce("add-dave"));
        request.expiry = expiry;
        bytes32 digest = _hashValidator(request);
        vm.expectRevert(abi.encodeWithSelector(IValidatorManager.RequestExpired.selector, expiry, now_));
        manager.changeValidator(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)), _sign(DAVE_PK, digest));
    }

    function _nonce(string memory label) internal pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    function _assertSignatures(bytes32 digest, bytes memory signatures) internal view {
        manager.assertValidatorSignatures(digest, signatures, block.timestamp + 1 days, _nonce("attestation"));
    }

    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("ValidatorManager")),
                keccak256(bytes("1")),
                block.chainid,
                verifyingContract
            )
        );
    }

    function _hashValidator(IValidatorManager.ChangeValidatorRequest memory request)
        internal
        view
        returns (bytes32)
    {
        return _hashValidator(address(manager), request);
    }

    function _hashValidator(address verifyingContract, IValidatorManager.ChangeValidatorRequest memory request)
        internal
        view
        returns (bytes32)
    {
        return MessageHashUtils.toTypedDataHash(
            _domainSeparator(verifyingContract),
            keccak256(
                abi.encode(
                    manager.CHANGE_VALIDATOR_TYPEHASH(),
                    request.validator,
                    request.isValidator,
                    request.expiry,
                    request.nonce
                )
            )
        );
    }

    function _hashQuorum(IValidatorManager.ChangeValidatorQuorumRequest memory request)
        internal
        view
        returns (bytes32)
    {
        return MessageHashUtils.toTypedDataHash(
            _domainSeparator(address(manager)),
            keccak256(
                abi.encode(
                    manager.CHANGE_VALIDATOR_QUORUM_TYPEHASH(),
                    request.quorum,
                    request.expiry,
                    request.nonce
                )
            )
        );
    }

    function _twoValidators() internal view returns (address[] memory initial) {
        initial = new address[](2);
        initial[0] = alice;
        initial[1] = bob;
    }

    function _addRequest(address validator, bytes32 requestNonce)
        internal
        view
        returns (IValidatorManager.ChangeValidatorRequest memory)
    {
        return IValidatorManager.ChangeValidatorRequest({
            validator: validator,
            isValidator: true,
            expiry: block.timestamp + 1 days,
            nonce: requestNonce
        });
    }

    function _removeRequest(address validator, bytes32 requestNonce)
        internal
        view
        returns (IValidatorManager.ChangeValidatorRequest memory)
    {
        return IValidatorManager.ChangeValidatorRequest({
            validator: validator,
            isValidator: false,
            expiry: block.timestamp + 1 days,
            nonce: requestNonce
        });
    }

    function _quorumRequest(uint8 quorum, bytes32 requestNonce)
        internal
        view
        returns (IValidatorManager.ChangeValidatorQuorumRequest memory)
    {
        return IValidatorManager.ChangeValidatorQuorumRequest({
            quorum: quorum,
            expiry: block.timestamp + 1 days,
            nonce: requestNonce
        });
    }

    function _setQuorum(uint8 quorum) internal {
        IValidatorManager.ChangeValidatorQuorumRequest memory request = _quorumRequest(
            quorum,
            keccak256(abi.encodePacked("set-quorum", quorum))
        );
        bytes32 digest = _hashQuorum(request);
        manager.changeValidatorQuorum(request, _signSorted(digest, _pks(ALICE_PK, BOB_PK)));
    }

    function _remove(address validator, bytes32 requestNonce, uint256[] memory pks) internal {
        IValidatorManager.ChangeValidatorRequest memory request = _removeRequest(validator, requestNonce);
        bytes32 digest = _hashValidator(request);
        manager.changeValidator(request, _signSorted(digest, pks), bytes(""));
    }

    function _pks(uint256 a, uint256 b) internal pure returns (uint256[] memory pks) {
        pks = new uint256[](2);
        pks[0] = a;
        pks[1] = b;
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signSorted(bytes32 digest, uint256[] memory pks) internal pure returns (bytes memory signatures) {
        for (uint256 i = 0; i < pks.length; i++) {
            for (uint256 j = i + 1; j < pks.length; j++) {
                if (vm.addr(pks[j]) < vm.addr(pks[i])) {
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
        for (uint256 i = 0; i < pks.length; i++) {
            signatures = bytes.concat(signatures, _sign(pks[i], digest));
        }
    }
}
