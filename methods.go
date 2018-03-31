package bturn

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

	ChannelBindRequest          = 0x0009 //(only request/response semantics defined)
	ChannelBindingResponse      = 0x0109
	ChannelBindingErrorResponse = 0x0119

	// SendMethod             = 0x006 //(only indication semantics defined)
	// DataMethod             = 0x007 //(only indication semantics defined)
	// CreatePermissionMethod = 0x008 //(only request/response semantics defined)
)
