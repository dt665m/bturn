package bturn

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
