// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MSA as MSA_ValidatorInNonce } from "./MSA_ValidatorInNonce.sol";
import "solady/auth/Ownable.sol";

contract MSA is MSA_ValidatorInNonce, Ownable {
    function execute(
        address target,
        uint256 value,
        bytes calldata callData
    )
        external
        payable
        virtual
        override
        returns (bytes memory result)
    {
        // only allow ERC-4337 EntryPoint OR self OR owner (Ownable)
        if (!(msg.sender == entryPoint() || msg.sender == address(this) || msg.sender == owner())) {
            revert AccountAccessUnauthorized();
        }
        result = _execute(target, value, callData);
    }

    function initializeAccount(bytes calldata data) public virtual override {
        _initializeOwner(msg.sender);
        super.initializeAccount(data);
    }
}
