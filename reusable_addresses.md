# BCH Reusable Address Proposal

BIP-???

v0.5.0, changes and clarification on derivation process

@im_uname, with material from Mark Lundeberg, plus discussion with Chris Pacia, Amaury Séchet, Shammah Chancellor, Jonathan Silverblood and Josh Ellithorpe. Additional editing from Freetrader, Emergent_reasons and Jonald Fyookball.

# Introduction

**Problem statement**

Most of the Bitcoin Cash ecosystem today runs on payments to straight addresses that are hashes of public keys, whether in simple P2PKH or scripted P2SH. Addresses are pseudonymous, and can provide a good - though imperfect - level of privacy if the receiver uses a fresh address to transact every time. Despite the existence or proposal of various alias/handle systems, there still exists a major problem in that users have to make compromises between usability, privacy, security, recoverability and trustlessness.

**Solution**

We propose a new alias system that would allow senders to generate a fresh address for any recipient with a handle. Communicating the existence of the transaction happens on-chain --actually embedded in the transaction itself, without using OP_RETURN.  This is accomplished by combining the Elliptic-curve Diffie-Helman properties of bitcoin keys with a simple grinding system, resulting in a byte-prefix that can be found by scanning while also hiding within an acceptable anonymity set.

This draft reusable address format, if widely adopted, seeks to provide a major improvement over existing systems in terms of net gain in all five areas, as well as more flexibility in choosing desirable compromises depending on usecases under one common format.

# Part I: Design Discussion


## Requirements

1. From only the paycode, sender can generate addresses that are detectable and spendable by the recipient.

2. Multiple payto addresses can be generated to a single recipient from a single notification, so amount can be obfuscated.

3. The sender can generate the recoverable payto address relevant to his payment, but cannot otherwise compromise the privacy or fund security of the recipient by deriving any of his private keys.

4. The transactions should have a reasonable anonymity set, where the recipient's transactions are not easily isolated on the blockchain.

5. The receiver must be able to separate the keys used to generate and detect addresses from the keys used to spend (which can be offline), so to separate the privacy and security aspects.

6. To remain light wallet compatible, the system must be able to reduce the number of transactions for the recipient to detect to a subset of all transactions, even at higher total transaction throughputs.

7. The transaction and notification must be self-contained, no additional transaction is needed to send a payment, no additional data other than the transaction itself is needed to receive and spend it. Derived addresses do not need to continue to be monitored after a transaction is detected.

8. There must exist a practical way for the recipient to recover his funds from mnemonic seed backups without compromising security or privacy.

9. Multisignature addresses must be supported for both sender and recipient.

10. Inputs and outputs can be in any order, so trustless coin mixing can be flexibly accommodated.

11. Compatible with other OP_RETURN protocols, which form an important part of the Bitcoin Cash ecosystem. Incompatibility may lead to low adoption or fragmented anonymity sets.

12. For offline notification methods, the intermediary servers must not be able to compromise security of funds.


## Existing payment systems both in use and theoretical

***Simple HD wallets***

Probably the most widely used format in Bitcoin Cash for both person-to-person and merchant transactions, HD wallets simply supply a new address to the sender for each transaction either through direct interactions (such as chat channels or face-to-face talks) or payment processing software. It provides a high amount of privacy as long as the communication channel is not public, as well as reasonable security and recoverability, as the HD seed is easy to store and make redundant.

However, this method delivers a considerable compromise in usability: For it to operate as intended, the parties must interact for a given transaction, which is more difficult for usecases such as donations and casual transactions without fumbling for phones. More importantly, this is difficult to execute if one attempts to translate addresses into easy-to-recognize payment handles, where the sender has to find either an intermediary or the recipient's wallet and fetch a new address for every transaction.

***Single-address***

Widely used in donation usecases, single-address recipients provide high transparency and easy usability: The recipient does not have to be online to receive funds. It is also very easily represented by consumer-friendly handles due to one-to-one mappability, as currently implemented by [CashAccounts](https://gitlab.com/cash-accounts/specification).

While it provides good usability, security and recoverability, single-address use is terrible in privacy, as one published address allows every person who is aware of her ownership of the address to know all of her other transactions. As privacy often also implicates real life safety, this is highly undesirable in the quest to improve usability.

***Trusted relaying intermediaries***

In light of the complications associated with the currently used systems above, some solutions such as OpenCAP and HandCash seek to provide intermediate, always-online services that simply relay HD addresses to senders. This solves quite a few problems: Usability can be improved because the server is always online, hence easier to find via lookups from static handles; privacy is theoretically as good as HD wallets as long as one trusts the servers; and recoverability is the same as any seed-based solution.

However, introducing a third party to relay degrades both security and trustlessness. The third party can relay false addresses to senders, resulting in theft, and a service that serves a large number of clients can also be hacked, resulting in massive loss of service and money. Furthermore, privacy is always trusted to the server, and existing solutions generally rely on DNS as an identifier to senders, making it difficult for recipients who wish to remain trustlessly private to run their own servers. As time goes on, we can expect such services to concentrate in fewer and fewer hands, where their trusted nature will increase the attack surfaces for both security and privacy even if the operators' intentions remain good.

***BIP-47 Payment codes***

[BIP47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki), proposed by Justus Ranvier, is a radical divergence from the traditional recipient-hands-address-to-sender model. Rather, recipients publish a single public key that any sender can read. The sender then first publishes a "notification" that tells the recipient of the sender's public key, either through sending to a public notification address or through offchain channels, followed by an actual funding transaction whose receiving address is derived via Diffie-Hellman to be only identifiable by the sender and recipient. If used in an ideal setup, it theoretically offers great improvements at all fronts: Usability is improved due to the use of single identifiers, privacy is great among repeat transacting parties, security is not compromised, and recoverability from seed is possible in the case of public notification.

When weighed against real life usecases and wallets, BIP47 does, however, present several challenges:

1. One has to choose either degraded privacy or degraded recoverability. In the case of public notifications, privacy is degraded for a majority of transactions. Most bitcoin transactions are between parties who interact for the first time; recurring transactions are rare, and may remain so for a long time until worldwide adoption - a public notification allows for trivial timing correlation of transactions, narrowing down possible transactions for any given recipient to a trivially small subset. If one opts for offchain notification, and if the recipient loses their backup of any public key notifications - typically harder to store and keep secure than seed words - then funds for the wallet may not be recoverable.

2. Implementation is complicated: If notification is onchain, a given wallet has to send two transactions to a first time recipient, and possibly obfuscate timing if one wants to have any semblance of privacy. This greatly complicates implementation difficulty, and creates additional problems in optimizing user experience, not to mention creating a disincentive to use such a system due to additional transaction fees. Offchain notifications lessen the burden, but then raise other questions in terms of recoverability (see above) as well as spam control.

***BIP-Stealth***

Originally proposed by [Peter Todd](https://github.com/genjix/bips/blob/master/bip-stealth.mediawiki) and later implemented by Chris Pacia, BIP-Stealth seeks a different path from BIP-47 in that it directly encrypts and embeds the sender's public key "notification" for each transaction in an op_return of the funding transaction, as well as attaching a prefix that allows the recipient to filter for his own transactions. The specification excels in its relative simplicity of implementation - there is only one transaction - as well as remaining recoverable from seed due to the fact that notifications are embedded, not to mention remaining trustless and secure. In fact, this proposal will reuse many of the same techniques as BIP-Stealth.

However, BIP-Stealth is still not ideal for several reasons:

1. Small anonymity set: Unless transactions across the ecosystem widely adopt BIP-stealth, transactions with an attached Stealth OP_RETURN will remain a very small subset of all transactions. In practice, this will mean a low level of privacy for its users for the foreseeable future, as users will have their transactions trivially identified from both timing and prefixes.

2. Incompatible with other OP_RETURN protocols: While this may be addressed in a future change in standardness rules, right now Bitcoin Cash only allows one OP_RETURN output per transaction. Embedding notifications inside OP_RETURN prevents the transaction from carrying other protocols such as Simple Ledger or CashIntents, limiting extensibility of the stealth transactions.

3. Flexibility in scaling: While BIP-Stealth does provide some flexibility in anonymity sets via adjusting prefix lengths, it does not provide means for low-bandwidth/trusted-privacy alternatives in offchain notification, nor does it provide for an expiry notice for clients who might want to update the address for scalability or privacy reasons periodically.

## Highlights of features in this proposal

Usability: Sender does not require any additional information aside from the paycode. (REQ-1)

Usability and implementation ease: One single specification, two ways to transact - with the offchain method sharing a common gateway format for senders to minimize wallet burden, while maximizing flexibility on receiving side allowing them to entrust privacy to intermediaries. (REQ-5)

Funds sent in one transaction: No setup. Possible second clawback transaction if offchain notification is not acknowledged. (REQ-7)

Privacy: Transaction indistinguishable from "normal" p2pkh/p2sh-multisig transactions, and has anonymity sets approximating a fraction of all transactions defined by the specified prefix. Sender does not know other transactions sent to the recipient. (REQ-3,4)

Privacy: For transactions with multiple inputs and outputs, it will be unclear to an observer which input is intended to be used for filtering as well as which output(s) are intended for the recipient (REQ-2,10)

Recoverability: Funds in the entire wallet recoverable by only seed phrases, with the help of a recovery server that does not have to compromise privacy. (REQ-8,6)

Usability: Can receive from P2PKH or P2SH-multisig addresses, covering the vast majority of usecases. Theoretically possible to receive from any P2SH script with a pubkey and signature, but might result in wallet implementation complications. (REQ-9)

Usability: Can receive to P2PKH or P2SH-multisig addresses, with payment codes adjusted accordingly. (Req 9)

Usability: Compatible with OP_RETURN protocols such as Simple Ledger Protocol, CashIntents or OMNI without adjusting current network protocol. (REQ-11)

Security: None of the servers, even "trusted" retention servers, have the ability to redirect or steal funds. The worst they can do is denial of service, which can be circumvented by falling back to recovery servers. (REQ-12)

Optional retirement: Ability for addresses to "renew" by expiring and republishing with adjusted resource usage after some period. Also useful for addresses where the recipient intends to stop monitoring after a period of time for other reasons. (REQ-6 related)

# Part II: Proposal Details

## Paycode format

For a recipient who intends to receive to a p2pkh addresses, encode the following in base32 using the same character set as cashaddr:

| Field Size | Description | Data Type  | Comments |
| -----------|:-----------:| ----------:|---------:|
| 1 | version | uint8 | paycode version byte; 1 and 2 for p2pkh (mainnet), 5 and 6 for p2pkh (testnet), among them 2 and 6 to force offline-communication only. |
| 1 | prefix_size | uint8 | length of the filtering prefix desired, 0, 4, 8, 12 or 16 bits for versions 1 through 8 ; 0 if no-filter for full-node or offline-communications. If used, recommend >= 8. |
| 33 | scan_pubkey | char | 256-bit compressed ECDSA/Schnorr public key of the recipient used to derive common secret |
| 33 | spend_pubkey | char | 256-bit compressed ECDSA/Schnorr public key of the recipient used to derive payto addresses when combined with common secret |
| 4 | expiry | uint32 | UNIX time beyond which the paycode should not be used. 0 for no expiry. Use 0 for versions 1,2,3,4. |
| 5 | checksum | char | checksum calculated the same way as [Cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#bch). |

For a recipient who intends to receive to a p2sh-multisig addresses, encode the following in base32 using the same character set as cashaddr:

| Field Size | Description | Data Type  | Comments |
| -----------|:-----------:| ----------:|---------:|
| 1 | version | uint8 | paycode version byte; 3 and 4 for p2sh-multisig (mainnet), 7 and 8 for p2sh-multisig (testnet), among them 4 and 8 to force offline-communication only. |
| 1 | prefix_size | uint8 | length of the filtering prefix desired, 0, 4, 8, 12 or 16 bits for versions 1 through 8 ; 0 if no-filter for full-node or offline-communications. If used, recommend >= 8. |
| 4 bits | multisig_setup_m | uint4 | instruction on constructing the multisig m-of-n to be paid to. m parties who can recover funds. m > 1, m <= n |
| 4 bits | multisig_setup_n | uint4 | instruction on constructing the multisig m-of-n to be paid to. n parties total. n > 1, m <= n |
| 33 | scan_pubkey | char | 256-bit compressed ECDSA/Schnorr public key of the recipient used to derive common secret |
| 33 | spend_pubkey1 | char | First compressed ECDSA/Schnorr public key of the recipients |
| 33 | spend_pubkey2 | char | Second compressed ECDSA/Schnorr public key of the recipients |
| ... | ... | ... | ... |
| 33 | spend_pubkeyn | char | nth compressed ECDSA/Schnorr public key of the recipients |
| 4 | expiry | uint32 | UNIX time beyond which the paycode should not be used. 0 for no expiry. Use 0 for versions 1,2,3,4. |
| 5 | checksum | char | checksum calculated the same way as [Cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#bch). |

The payment code shall be prefixed with `paycode:`, and can be optionally suffixed with offchain communications networks it supports in URI, e.g. `?xmpp=johndoe@something.org&matrix=@john123:something.com`. If no additional suffix is detected, the default offchain relay method, a necessity for version 2, 4, 6 and 8, is Ephemeral Relay service (see below).

## Private key format

For the easy facilitation of paper wallets and inter-wallet transfers, the scan private key shall begin with "rpriv", the spend pubkey "spriv", followed each by these fields encoded in base32 using the same character set as cashaddr:

| Field Size | Description | Data Type  | Comments |
| -----------|:-----------:| ----------:|---------:|
| 1 | version | uint8 | paycode version byte |
| 1 | multisig_setup | uint4 + uint4 | instruction on constructing multig m-of-n (see above). 0 on both if P2PKH |
| 1 | prefix_size | uint8 | length of the filtering prefix desired, 0, 4, 8, 12 or 16 bits for versions 1 through 8 ; 0 if no-filter for full-node or offline-communications. If used, recommend >= 8. |
| 33 | privkey | char | 256-bit ECDSA/Schnorr private key |
| 5 | checksum | char | checksum calculated the same way as [Cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#bch). |

## Paycode creation from two keypairs (P2PKH)

Obtain two ECDSA/Schnorr keypairs from a wallet, and designate one as the "scanning" pubkey and the other as the "spending" pubkey.

Any common-secret-derived keypairs detected from incoming payments are additionally stored in the wallet file for history and spending, to minimize future bandwidth and CPU usage. Historical receive addresses do not need to be continuously monitored after first receipt. The expiry date should be set to 0 to remain disabled.

**Paycode creation (P2SH-multisig)**

The multisig m-of-n parties do not keep transaction scanning privacy from each other, and must agree on a common scanning keypair. They can subsequently submit one ECDSA/Schnorr spending pubkey each, and set up the paycode using the n+1 public keys. The expiry date should be set to 0 to remain disabled.

## Receipt of transactions sending to a reusable address

Receiving wallets must follow a specific process, detailed here, to detect payment code transactions that are directed at them. Following this process, or an equivalent, ensures that any valid payment code transaction can be identified by a conforming receiver, and thus no funds will be missed. The process of generating such transactions is described in a later section.

In short, this process consists of two scanning steps:

1. Prefix filtering: all transactions have their inputs scanned for a short tag prefix that publically classifies the payment code.

2. For every input that matched in the previous step, a shared secret derivation process is performed using the input's spending key, and the reusable address scan key. The output list of the enclosing transaction is then scanned for one or more output addresses derived from the shared secret and the reusable address spend key.

As detailed in the later sections, these two steps are designed so they can be performed by different parties.

### Prefix filtering

The prefix-filtering step requires the full blockchain and knowledge of the payment code. It produces a list of matching transaction inputs.

1. All transactions in the blockchain and mempool must be scanned, except:
    - coinbase transactions
    - old transactions from blocks that are known to predate the creation of the payment code system (or the target payment code itself).

2. For every transaction, the first 30 inputs are examined. Inputs after the first 30 are ignored.

3. For every input, an input-hash is calculated by serializing the input record as in a raw transaction (Outpoint, len_scriptsig, scriptsig, nSequence), and computing a *double*-SHA256 of this serialized result. The filter matches if the leftmost `prefix_size` bits of the input-hash match the target prefix bitstring.

4. The target prefix bitstring is derived from the payment code as follows: take from the leftmost `prefix_size` bits, skipping the first 8 bits, in the compressed-serialized scan public key (the first byte is skipped due to having low entropy). In other words, it is the highest `prefix_size` bits of the scan public key's X coordinate when expressed as a fixed-width 256-bit integer.

Steps 1-3 are intended to be optimized by building an index of the blockchain, ahead of time. When given a target payment code, the index can be efficiently consulted to yield the list of matches.

### Address derivation process

The address derivation process requires a candidate transaction input (an input with a matching prefix, as in the prefix filtering step) as well as the enclosing transaction, the scan *private key*, and the spend public key(s). It produces a list of matching addresses and the key offset(s) for each one.

Every candidate input generates a sequence of output addresses which may or may not appear in the transaction. The derivation process depends on the input type (p2pkh or multisignature) and the payment code type (p2pkh or multisignature). Steps:

1. A sender public key `P` is extracted from the input.
    - In the case of P2PKH inputs, `P` is simply the spending public key.
    - In the case of P2SH-multisig inputs, `P` is the public key of the first valid signature.
        - For legacy multisignatures (null dummy element), the receiver MUST verify signatures against the public keys in the same order as used in the script execution engine, starting from deepest-in-stack, i.e., first-pushed. Then, `P` is the public key used in the first ('leftmost') successful signature verification. Note: Implementations MUST be able to correctly validate signatures with any valid SIGHASH flags, in order to properly determine `P`. Pre-BCH legacy signatures can be ignored, as they predate this specification.
        - For the newer BCH multisignature style (non-null dummy element), it is not necessary to verify signatures and `P` is the first-pushed pubkey indexed by the least-significant set bit in the dummy (checkbits) element. The push opcode that pushes the checkbits element MUST be correctly parsed in all cases, whether it uses OP_1-OP_16 opcodes or the OP_PUSHDATA*n* opcodes. Note: Even though non-null dummy had legacy mechanics prior to 2019, implementations need not take care of this distinction since it predates this specification's existence.
        - Invalid public keys in the multisignatures are consensus-valid in some cases. Receivers are not expected to recognize such weird multisignatures.
    - Other input types (P2SH non-multisig, P2PK, etc.) shall be skipped.
    - To be clear, what we count as 'P2PKH' or 'P2SH-multisig' must have a specific form of scriptPubKey *and* the scriptSig for that input (both locking and unlocking scripts). This is more strict than most definitions of these types of inputs:
        - As usual, a P2PKH scriptPubKey is exactly 25 bytes long of the form (in hex) `76a914<20 byte keyhash>88ac` (no non-minimal pushes). A P2SH scriptPubKey is 23 bytes long of the form `7614<20 bytes scripthash>87`.
        - A P2PKH scriptSig has exactly two minimal pushes, with the form `<sig> <pubkey>`, where `sig` is a validly formatted schnorr or ECDSA (DER) signature with any value of the hashtype byte, and `pubkey` is either a compressed or an uncompressed key.
        - An M-of-N P2SH-multisig scriptSig has exactly M+2 pushes of the form `<dummy> <sig1> <sig2> ... <sigM> <redeemscript>`, where `redeemscript` is a serialized script that itself parses to `OP_M <pub1> <pub2> ... <pubM> OP_N OP_CHECKMULTISIG`, both scripts with minimal pushes. Each `sig` is a validly formatted schnorr or ECDSA (DER) signature with any value of the hashtype byte, and each `pub` is either a compressed or uncompressed key. The value of `dummy` may be anything (and it may be any kind of push including OP_1 through OP_16).
            - Current network rules about the interpretation of the multisig dummy value and the uniformity of signature type (schnorr / ecdsa) must not be assumed, as these may change in future.
        - Note that both uncompressed and compressed keys must be allowed.
        - Receivers are not required to detect P2PKH or P2SH-multisig inputs that do not exactly fit these descriptions. However, receivers may find it convenient to use more flexible definitions than stated here. For example, it is a burden to fetch the ancestor transaction (to view scriptPubKey) in every case. Thus, it is permissible for receivers to solely examine the scriptSig of the candidate input. (At worst, more liberal rules result slightly more CPU work than is strictly needed).
2. The elliptic curve point `Q = d · P` is calculated, where `d` is the scan private key (this is a Diffie-Hellman derivation). This point is then serialized as a compressed point and then hashed with SHA256, to yield a 32-byte shared secret value `s`. I.e.: `s = SHA256(ser_comp(Q))`.
3. The input's spent outpoint is serialized to a length-40 bytestring `outpoint` in the same way as it is serialized in the raw transaction (the txid is "reversed" compared to display order, and the index is little-endian).
4. A further 32-byte commmon secret value `c` is calculated as `c = SHA256(s || outpoint)`, where `||` denotes concatenation.
5. The address sequence is derived using `c` and the spending public key(s), and an index `i`.
    - For a p2pkh payment code, the address sequence at index `i` is calculated via [BIP32 unhardened derivation](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Public_parent_key_rarr_public_child_key), i.e. `R_i = CKDpub(R,c,i)`. This provides a pseudorandom sequence of additive offsets to `R`, based on `c`. The resultant public key is serialized compressed then hashed to a P2PKH address.
    - For a multisignature paycode, first each spending public key is passed into the same unhardened derivation: R1'<sub>i</sub> = CKDpub(R1,c,i), R2'<sub>i</sub> = CKDpub(R2,c,i) and R3'<sub>i</sub> = CKDpub(R3,c,i), etc.. The resulting keys are serialized as compressed, then the serialized keys are sorted lexically (as per BIP67 / `sortedmulti` descriptors). The standard P2SH multisignature script is then assembled from the sorted list as `OP_M <sortedkey1> <sortedkey2> ... <sortedkeyN> OP_N OP_CHECKMULTISIG`, and hashed to a P2SH address.
6. The output list is scanned for outputs to the address derived using `i=0`. If a match is found, or if the BIP32 derivation fails for this index (CKDpub fails with a 2^-127 probability), then the output list is scanned again for outputs to the address derived using `i=1`. This process continues with `i=2`, `i=3`, etc. until an index is found where BIP32 derivation succeeded but no match is found.
    - Note: Receivers MUST recognize multiple outputs to the same address, so long as they are in the same enclosing transaction.
    - Note: Receivers MUST recognize multiple inputs paying to the same payment code.
    - Note: Receivers are not required to detect other outputs to these same addresses that exist in other transactions.

This process produces a list of the addresses identified in step 5, and the key offset(s) for each. The key offset(s) can then be combined with the reusable address spending private key(s) to determine the actual private keys associated with the address in question.

## Generating a transaction to payment code

Sending money to a payment code means creating a transaction that will be recognized by the above process. Conforming wallets must not create transactions that cannot be discovered by the above process, since it means a loss of funds.

Note: only P2PKH wallets or P2SH-multisignature wallets may send to payment codes.

The recommended basic process is as follows:

1. Sender's wallet shall first check that the expiry time embedded in the paycode is at least one week ahead of local clock (skip if expiry time is 0). If expiry time is more than a week ahead, proceed.
2. An unsigned transaction template is created in the regular manner, but using a placeholder output address for the recipient.
3. Once input coins have been selected, a random input within the first 30 inputs is chosen.
4. The selected input is then analyzed and an address sequence derived.
    - The derivation proceeds almost the same as describe above with receiving, except now `Q = D · p` where `D` is the scan *public* key, and `p` is the *private key* corresponding to the input's `P`.
5. The placeholder output address is then overwritten with the `i=0` derived address.
    - (optional) Output addresses are re-sorted according to BIP69.
6. The transaction is then fully signed. The chosen special input is then re-signed repeatedly to produce different prefixes, until it has the correct prefix ("prefix grinding"). See below for recommendations on this process.

For multisignature wallets, additional care must be taken to avoid funds loss (where the recipient is unable to detect the payment):

- The intended signing set must be identified ahead of time, so that the intended first-used key `P` can be decided.
- The first-used signer should provide a "proof of equality of discrete logarithms" to the other signers, in order to demonstrate that the Diffie-Hellman secret is correct and that they can be confident that the output goes to the intended recipient.
- Signers must ensure that the last signer properly executes signature grinding to obtain the correct tag.
- Signers must not re-sign and malleate the tag.
- Uninvolved cosigners must not introduce a signature of their own, which would not only malleate the tag but also potentially change which key is the first-used key.
- Given the above difficulties, cosigners should keep a receipt of the `c` value. In case it turns out that the intended recipient did not see the funds, this information can be sent directly to them and then used to recover funds.

In addition:

- The first-used signer must not use a key which they use to receive encrypted messages (or is related to such a decrypting key), or else they could be tricked by their cosigners into decrypting a message by having a malicious scan public key in a payment code.

For cold wallets, some of the concerns from multisignature wallets also apply.

### Note on prefix grinding

Grinding the prefix is accomplished by modifying the transaction input data until the prefix or its hash matches the desired value. The best way to accomplish this is to simply re-sign the input using a different cryptographic nonce "k" value. For observers, the fact that a nonce has been varied like this is essentially undetectable.

Since bitcoin transactions do not have explicit nonces (unlike blockheaders), the nonce in this case is the random-looking integer "k" value used in creating the transaction signature.  Wallets that already use random "k" can simply keep re-selecting random values as the grinding process.

There are serious security concerns about actually using random nonces (an imperfect random source can easily lead to a leakage of the private key), so most wallets will in fact be using RFC6979 for deterministic signatures. In such wallets, simply re-signing the input will change nothing. However, the RFC6979 process allows for additional data to be attached, and by rotating this additional data (for example, setting it to an integer 0 and incrementing on every attempt), a securely pseudorandom stream of distinct nonces is produced.

### Cautions

To reiterate, it is important to not generate transactions that will be unrecognized by a receiving wallet. To emphasize some important 'gotchas':

- The correct input (the same used to derive the addresses) must be used for grinding the prefix. It must be within the first 30 inputs.
    - Even when there is no grinding (prefix length is 0), the input used for derivation must still be within the first 30 inputs.
- As mentioned above, when sending normally from multisignature wallets, it is simply impossible to securely ensure that funds will reach the intended recipient. Mistakes with multisignatures could easily happen on accident in a typical multisignature coordination, and multisig wallets should caution users about this risk.
- Sending wallets must make sure that the scriptSigs properly fit the heuristic template process described. Notably:
    - M-of-N multisignature wallets with N > 16 cannot be used to send to a reusable address, since these do not use OP_*n* in the P2SH redeemscript.
    - Multisigs with invalid pubkeys are sometimes valid in consensus rules, but they will be excluded by the template.
- Senders must not skip indices in the derived addresses list. For example, receivers will not check `i=1` if there was nothing on `i=0`.
- Future upgrades may potentially break certain assumptions behind this specification. Wallets must keep up-to-date and remove any accidentally introduced abilities to create payments that will fail to be detected by existing receiving wallet implementations. This specification may need updates to clarify or extend in light of new rules.
    - Any new transaction formats must not be used for payment code transactions.
    - A hypothetical taproot upgrade might permit P2PKH spending with more than two pushes; such P2PKH spends would be ignored by the scriptSig templates.
    - A new crypto system with a new key type (non-secp256k1, i.e., neither compressed nor uncompressed) would fail detection by the described templates.
    - A new signature type will also not match the templates.
    - New malleability vectors may be introduced.

## Relaying: Infrastructure needed

There are two methods of receiving: ***Offchain communications***, which saves on bandwidth but entrusts privacy to relay and retention servers, and ***onchain direct sending***, which is trustless on privacy but requires more bandwidth. We describe a single type of server required for both types, as well as two additional types required to make use of the offchain communications method:

1. ***Recovery servers***: In case of onchain direct sending, only this type of server is needed. The server shall index all transactions that have P2PKH or P2SH-multisig inputs by the last bytes of the double-sha256 at all qualifying inputs, and return all transactions matching requested input double-sha256 prefixes to a client. Required for security anyway in the case of offchain communications. See recovery_server.md for specifications.

2. ***Ephemeral Relay servers***: (Optional) This type of server can be freely signed up for using only public keys as identity, authenticating using signed messages as seen in CashID, and can employ basic rate controls against clients as seen in CashShuffle servers and remain largely permissionless. Simplistically relays encrypted messages from one pubkey identity to another. We can start with one central relay server, and gradually expand to multiple federated servers that share communications - a discovery mechanism should be in place similar to other decentralized applications. Does not store information for any significant lengths of time, stateless, and mostly consumes only bandwidth. See relay_server.md for specifications.

3. ***Retention servers***: (Optional) This type of server retains transaction information for offline clients, and can be permissioned while allowing significant innovation and profit models at scale. Entrusted with client scan keys, retention servers connect to relay servers for their clients, then retrieve, decrypt and broadcast transactions for them. They are also responsible for retaining txid information for easy retrieval when client reconnects. Operators of Retention Servers can be expected to also operate their own Ephemeral Relays federated with other operators. An example that takes advantage of CashAccounts can be found at cashaccounts_retention.md.

## Sending: Onchain direct sending

After a transaction is generated, if the sending wallet detects the version allows onchain direct sending, it can simply broadcast the transaction to the Bitcoin Cash network and let it be mined. No notification to the recipient is needed.

## Receiving: Onchain direct

If onchain direct sending is used, receiving is relatively straightforward. The recipient shall connect to a Recovery Server and attempt to download all transactions with inputs that match his payment code's prefix. This will cost bandwidth that is approximately 1/256 of downloading the full blockchain (in the case prefix length = 8 bits; recovery servers may choose to deny excessively short prefix lengths), and less if longer prefix length is specified.

Upon receiving subscribed transactions, the wallet can then derive addresses out of each input that matches the prefix. If matches are found, the wallet can then store the key offset and address. As soon as the spending private key is also available (which may be immediately), then the final derived private key can be derived as well.

## Sending: Offchain communications

(Optional) If the paycode specifies offchain communications via setting the version byte and does not specify additional relay methods, the sending wallet shall attempt to relay through Ephemeral Relay servers. The constructed transaction shall first be encrypted with the payment code's scan pubkey, using a common ECDSA-based scheme such as [electrum-ECIES](https://github.com/Electron-Cash/Electron-Cash/blob/master/lib/bitcoin.py#L690), then handed off to a relay server. The transaction is considered "Sent" when the sending wallet detects the same transaction being broadcasted by a retention server.

To remain trustless against the possibility of relay or retention servers denying service, after a short timeout (e.g. 30 seconds), if the transaction is not detected, the sending wallet shall consider the broadcast failed and construct a "clawback" transaction that spends the same output to a new address she controls. This is to avoid the case where the trade is voided - recipient never sends goods or services to the sender - yet after some time the recipient broadcasts the transaction anyway, robbing the sender.

## Receiving: Offchain communications

(Optional) A Retention Server, subscribing to Relays using a client's scan privkey, receives the encrypted transaction, then decrypts and broadcasts to the Bitcoin Cash network; invalid transactions can be discarded. The server then proceeds to store the relevant txids calculated from the broadcasted transaction for its clients until retrieved - retention time can vary depending on provider, from several weeks to indefinite depending on specific quality of service desired.

Clients can log onto retention servers and retrieve their incoming txids. Depending on the level of service, the login method can be relatively permissionless (depending on CashAccounts, for example; see cashaccounts_retention.md) or permissioned in premium or other methods. Specific arrangements depend on the exact setup and can even be extended to use other communications protocols such as XMPP and Tox, to be determined by the implementing wallet.

After a client fetches a txid from the retention server, he should proceed to request the full transaction from a node, and extract spending keypair as described above. Then the transaction and spending keypair for its output should be stored locally.

Depending on the specific setup, if a client suspects either server downtime, malicious denial of service, or expired retention, it shall connect to a Recovery Server and attempt to recover funds as described in Onchain Direct transactions.

## Expiration time

Note: Expiry date is not expected to be relevant in the near term, so it's recommended that receiving wallets set it to zero when generating. Sending wallets are still recommended to implement it to remain compatible with possible future scalability and usability changes.

Whether it uses onchain direct sending or offchain communications, as long as the wallet remains compatible with seed recovery via recovery servers, it will require a fixed fraction of total Bitcoin Cash bandwidth for that purpose. While the consumption does not have to be latency sensitive in the context of a light wallet, it is vulnerable to long term total traffic fluctuation. If the prefix is too short while network traffic gets much higher, the wallet might have difficulty running as bandwidth requirement rises with network traffic. On the other hand, if the prefix is too long when network traffic is low, the wallet's privacy is degraded as its anonymity set shrinks, in addition to creating undue burden on sending wallets for grinding.

In order to mitigate this, an optional expiry time can be added; sending wallets shall respect the expiry time by yielding an error if attempting to send past it - any funds that are sent overriding the expiry is considered lost, and the recipient has done due diligence warning the sender in the paycode.

When scanning, nodes or wallets can allow for a certain amount of buffer beyond the expiry date, in case a transaction is sent before but remains unconfirmed beyond the expiry - in the context of BCH, a week might be more than sufficient.

In addition to addressing scaling concerns, expiration also addresses another usecase complaint - that wallets once established will have to monitor addresses indefinitely, and that there is no clear indicator to a sender whether an address remains usable or not. Such a clear guide embedded in the address itself can serve these cases well and provide unambiguous dates beyond which recipient will be free from the burden of maintaining monitoring and keys.

## Considerations

***Malleability considerations*** While using input hash as the filtering mechanism has advantage in both flexibility and implementation simplicity, input hashes are third-party malleable if colluded with a miner via nonstandard transactions, via exploiting vulnerabilities fixed in Bitcoin Cash's scheduled November 2019 upgrade (MINIMALDATA for P2PKH and NULLDUMMY for P2SH). Even before the fix, these DoS vectors - note that an attacker cannot steal funds - are mitigated by the fact that an attacker cannot easily pinpoint any given recipient's transaction.

***Limits of party combination*** The design allows multiparty inputs and multiparty payouts, with each recipient party capable of deriving multiple addresses for maximum privacy. However, the number of recipient parties must never exceed the number of inputs nor the 30-input limit in any given transaction; i.e. if you intend to pay to three independent parties, you must provide the transaction with at least three inputs, so each can provide for a filter prefix and public key for one of your recipients.

***Anonymity set*** Anonymity set for prefix_size 0 is effectively all transactions with p2pkh outputs (TBD p2sh-multisig); with prefix_size > 0, it is reduced by a factor of 1/2^(prefix_size) at each step for the simplest case where all transactions have only one input. The set may be larger where transactions contain more inputs, up to ~ 700/2^(prefix_size) in the worst case; for most usecases, though, wallets .

***Upper limit of scalability at recovery*** At very large blocksizes, the maximum prefix length possible by the spec is 2 bytes, or about a 1/65536 filter; for a full 128MB sized block, this will mean the client needs to examine about 281kB of data per day of recovery in the minimum case, more for average number of inputs per transaction above 1 - up to about 8.5MB/day in the worst case where the chain is entirely filled with ~4kB, 30-input consolidations. Unless the disparity between client and server technologies change radically, this should be adequate for the forseeable future.

Note that for current versions the prefix length is limited to 16 bits, or 1/65536, which should be comfortable as described. As the chain grows even bigger, the prefix can be made longer to accomodate more filtering, at a cost of more computing power needed from senders.

***DoS via multiple inputs*** Since one transaction can map to multiple prefixes via its multiple inputs, it would seem possible to increase download burden for onchain direct users, as well as offchain users recovering from seed, by posting very large transactions with many inputs each with different prefixes. However, such a scheme will at most be able to amplify the attack of a 100kB transaction against 30 prefixes, which is likely insufficient to be a serious concern for most situations.

***Compatibility with coinjoin-based technologies*** While incoming addresses are only determined upon sending, coinjoin technologies such as Cashshuffle are quite agnostic to how receiving addresses are generated. The more important aspects of these technologies are that 1) addresses are not reused and 2) a ready list of change addresses can be generated from the same seed or master private key, both of which are compatible. Incoming coins can be marked for joins as they are received or recovered just as they can on HD addresses.
