## LoonySSH

Pure Dotty implementation of SSH protocol.

**Experimental hobby project written in a rapidly changing language!** Do not expect this to be production ready anytime soon.

### Plan

- Implement
    - [x] RFC Parser
    - [x] Names [`RFC 4250`](https://tools.ietf.org/html/rfc4250)
    - [ ] Transport [`RFC 4253`](https://tools.ietf.org/html/rfc4253)
        - [x] Generic Reader
        - [ ] Generic Writer
        - [ ] Make the `inline given`s non-recursive, as in `shapeless3` or use `shapeless3`, when it gets released
- Bootstrap from [`jsch`](https://github.com/is/jsch/blob/master/LICENSE.txt)
    - [x] Cherrypick few protocols to support
    - [ ] Authentication Protocol [RFC 4252](https://tools.ietf.org/html/rfc4252)
    - [ ] Connection Protocol [RFC 4254](https://tools.ietf.org/html/rfc4254)
- Bootstrap from [`ed25519-java`](https://github.com/str4d/ed25519-java)
    - [ ] `ssh-ed25519`

### Testing / DevOps

- [ ] Set up Travis / Pipelines
- [ ] Property Based Testing (Reader <-> Writer)