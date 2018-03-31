package bturn

import (
	"encoding/binary"
)

const (
	MagicCookie          = 0x2112A442
	TransactionIDLength  = 12
	HeaderLength         = 20
	Padding              = 4
	StunLengthPtr        = 2
	StunTransactionIDPtr = 4

	IPv4Flag     uint16 = 0x01
	IPv6Flag     uint16 = 0x02
	UDPTransport byte   = 17
)

var (
	be = binary.BigEndian
)

// errors
const (
	StatusTryAlternate                 = 300
	StatusBadRequest                   = 400
	StatusUnauthorized                 = 401
	StatusUnassigned402                = 402
	StatusForbidden                    = 403
	StatusUnknownAttribute             = 420
	StatusAllocationMismatch           = 437
	StatusStaleNonce                   = 438
	StatusUnassigned439                = 439
	StatusAddressFamilyNotSupported    = 440
	StatusWrongCredentials             = 441
	StatusUnsupportedTransportProtocol = 442
	StatusPeerAddressFamilyMismatch    = 443
	StatusConnectionAlreadyExists      = 446
	StatusConnectionTimeoutOrFailure   = 447
	StatusAllocationQuotaReached       = 486
	StatusRoleConflict                 = 487
	StatusServerError                  = 500
	StatusInsufficientCapacity         = 508
)

var errReasons = map[int][]byte{
	StatusTryAlternate:     []byte("Try Alternate"),
	StatusBadRequest:       []byte("Bad Request"),
	StatusUnauthorized:     []byte("Unauthorized"),
	StatusUnknownAttribute: []byte("Unknown Attribute"),
	StatusStaleNonce:       []byte("Stale Nonce"),
	StatusServerError:      []byte("Server Error"),
	StatusRoleConflict:     []byte("Role Conflict"),

	// RFC 5766
	StatusForbidden:                    []byte("Forbidden"),
	StatusAllocationMismatch:           []byte("Allocation Mismatch"),
	StatusWrongCredentials:             []byte("Wrong Credentials"),
	StatusUnsupportedTransportProtocol: []byte("Unsupported Transport Protocol"),
	StatusAllocationQuotaReached:       []byte("Allocation Quota Reached"),
	StatusInsufficientCapacity:         []byte("Insufficient Capacity"),
}
