package bturn

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

type Attribute uint16

// STUN Required Attributes
const (
	AttribMappedAddress     Attribute = 0x0001
	AttribUsername          Attribute = 0x0006
	AttribMessageIntegrity  Attribute = 0x0008
	AttribErrorCode         Attribute = 0x0009
	AttribUnknownAttributes Attribute = 0x000A
	AttribRealm             Attribute = 0x0014
	AttribNonce             Attribute = 0x0015
	AttribXORMappedAddress  Attribute = 0x0020
)

// STUN Optional Attributes
const (
	AttribSoftware        Attribute = 0x8022
	AttribAlternateServer Attribute = 0x8023
	AttribFingerprint     Attribute = 0x8028
)

// TURN Expanded Attributes
const (
	AttribChannelNumber      Attribute = 0x000C // CHANNEL-NUMBER
	AttribLifetime           Attribute = 0x000D // LIFETIME
	AttribXORPeerAddress     Attribute = 0x0012 // XOR-PEER-ADDRESS
	AttribData               Attribute = 0x0013 // DATA
	AttribXORRelayedAddress  Attribute = 0x0016 // XOR-RELAYED-ADDRESS
	AttribEvenPort           Attribute = 0x0018 // EVEN-PORT
	AttribRequestedTransport Attribute = 0x0019 // REQUESTED-TRANSPORT
	AttribDontFragment       Attribute = 0x001A // DONT-FRAGMENT
	AttribReservationToken   Attribute = 0x0022 // RESERVATION-TOKEN
)

const (
	ChannelDataStart         = 0x4000
	ChannelDataEnd           = 0x7FFE
	ChannelDataReservedStart = 0x8000
	ChannelDataReservedEnd   = 0xFFFF
)

// stun Methods
const (
	BindingRequest       = 0x0001
	BindingResponse      = 0x0101
	BindingErrorResponse = 0x0111
)

// turn Methods
const (
	AllocateRequest       = 0x0003 //(only request/response semantics defined)
	AllocateResponse      = 0x0103
	AllocateErrorResponse = 0x0113

	RefreshRequest       = 0x0004 //(only request/response semantics defined)
	RefreshResponse      = 0x0104
	RefreshErrorResponse = 0x0114

	ChannelBindRequest       = 0x0009 //(only request/response semantics defined)
	ChannelBindResponse      = 0x0109
	ChannelBindErrorResponse = 0x0119

	SendIndication          = 0x006 //(only indication semantics defined)
	DataIndication          = 0x007 //(only indication semantics defined)
	CreatePermissionRequest = 0x008 //(only request/response semantics defined)
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
