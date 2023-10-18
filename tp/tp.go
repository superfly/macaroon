package tp

const (
	InitPath = "/.well-known/macfly/3p"
	PollPath = "/.well-known/macfly/3p/poll"
)

type jsonInitRequest struct {
	Ticket []byte `json:"ticket,omitempty"`
}

type jsonInitResponse struct {
	Error           string               `json:"error,omitempty"`
	Discharge       string               `json:"discharge,omitempty"`
	PollURL         string               `json:"poll_url,omitempty"`
	UserInteractive *jsonUserInteractive `json:"user_interactive,omitempty"`
}

type jsonUserInteractive struct {
	PollURL string `json:"poll_url,omitempty"`
	UserURL string `json:"user_url,omitempty"`
}
