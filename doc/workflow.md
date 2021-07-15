# Workflow
The entire workflow can be divided into 2 big phases: server registration phase and communication phase.
The server can only be added during the first phase, while the client can only be added during the second phase.
The communication phase is has infinite rounds, each round consists of 5 phases: announcement, bridge post, bridge request, vote, and round end.

## Server registration
The coordinator waits for other servers to join the chain. Also all servers encrypt a perdersen HT together during the process. Only the coordinator records HT at the moment, but it will be broadcasted to all servers in communication phase.
* Each new server sends a registration request to the coordinator.
* + The coordinator records the new server's address, adding it to the chain's rear,
  + then tell this server its previous hop in the chain and perdersen HT.
  + Note the coordinator is also a member in the chain, so if there's no other server, the coordinator will be this new server's previous hop.
* The new server then
  + records its previous hop,
  + encodes HT with a random number and sends it back to the coordinator.
* The coordinator receives and records the new HT.

## Client registration
* The new client sends its public key to the coordinator.
* The coordinator
  + records the client's address and public key,
  + computes a pedersen commitment for its credit, which is 0,
  + then sends the register info to the next server in the chain,
  + and sends `r` (from pedersen commitment) and `g` to this client.
* For client,
  + it records `r` and `g`,
  + then computes its `nym` using its private key and `g`.
* For server,
  + once it receives a client register info,
  + it encrypts the info's public key `pk` with its own round key into `pk'`,
  + then sends it to the next hop.
  + Also it needs to record the mapping from `pk` to `pk'`.
* After the register info traverses through the chain and reaches back to the coordinator,
  + the coordinator records the public key (which should equal to client's `nym`) and pedersen commitment.
  + Then it sends some protocol configuration to this client.
* Client records the configuration, then compute a challenge for fujiokam parameters to coordinator.
* Coordinator then replies with an honesty answer.
* If the client can not verify the answer, it terminates. Otherwise the registration succeeds.

## Announcement phase
Coordinator has a table of each client's pseudo name (nym) and commitment.
But coordinator does not know the IP corresponding to nym.
* The coordinator sends a reputation key map, `GT` and `HT` to the next hop.
* After a server receives an announcement
  + it firstly encrypts `GT` and `HT` with a random number,
  + then verifies th previous shuffle if the announcement contains `g`,
  + also it encrypts this `g` with its roundkey, (if there's no such `g`, use base)
  + then encrypts the table and shuffles it,
  + and finally it sends everything including the original table to the next hop.
* In the end,
  + the coordinator receives announcement from the last server,
  + then it records `GT` and `HT`,
  + constructs decrypted reputation map,
  + and finally distributes `g` and table to clients.
  + actually the coordinator also needs to distribute `g` to all servers, but since in our implementation, only coordinator interacts with clients directly, other servers never need to use `g`.

## Bridge post
* Client sends to the coordinator a message of its `nym`, a bridge address and its signature (using its private key).
* The coordinator then
  + verify the signature using `nym`,
  + we assume clients never send duplicated bridges in our implementation,
  + bind this bridge with this `nym`, and tell other servers. (in our implementation, we do not need to tell other servers, as they do not interact with clients directly)

## Bridge request
* Client sends to the coordinator a message of its nym, a reputation indicator `ind`, a proof `prf` that its reputation >= `ind`, a signature of the entire message (including `nymR`, `ind` and `prf`) using its private key.
* The coordinator then
  + verify the signature using `nymR`,
  + verify the `prf` using all the information in the message,
  + select `ind` number of bridges and their `nym`, forming `ind` number of *assignment* tuples `(nymR, nym, bridge)`,
  + broadcast to all servers the above tuples and `prf`.
* Each server
  + verifies `prf`,
  + then sign all tuples using its private key,
  + then send these signatures back to the coordinator.
  + if verification failed, it replies with failure.
* After the coordinator received all servers' signatures,
  + it signs these tuples using its private key,
  + then sends these tuples and all signatures back to the client.
  + Then it records these bridges for further voting, and marks these bridges as used.

## Vote
* Client sends to the coordinator a voting message of an assignment tuple, all related signatures, a feedback score (+1/-1) and a signature of this message,
* The coordinator
  + verifies the client's signature,
  + verifies all servers' signatures,
  + record the bridge provider's score diff.

## Round end
* + Coordinator adds new clients' `nym` and commitments into reputation map,
  + updates existing clients' reputation maps using diffmap,
  + then sends the map and its `GT` and `HT` to the previous hop,
  + Also it sends pedersen `rDiff` to clients.
* Each client, if participated in this round, updates its pedersen `r` using the difference map.
* Each server after receives round end package,
  + decrypts all public keys in the map and randomize all commitments with a random number `E`,
  + encrypts `GT` and `HT` with `E`,
  + shuffles the map back,
  + then sends everything to the previous hop,
  + eventually resets round key and key map.
* In the end, the coordinator receives message from its next hop,
  + it records the map,
  + updates `GT` and `HT`,
  + compute the diff map,
  + then send the diff map to all users.
* Each client updates its own reputation using the diff map, then wait for new round to start.



# Coordinator

# Server

# Client
