# bturn
STUN - TURN implementation in Go

This is not a fully functional turn implementation.  Currently, bturn only supports allocations and communications through channel bindings ON BOTH PEERS.  Data/Send indications aren't implemented.  Binding more udp socket ports per client is a work in progress.  