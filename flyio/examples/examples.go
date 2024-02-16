package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
)

//go:generate go run .

var header = strings.ReplaceAll(strings.TrimSpace(`
# Fly.io Token Attenuation Examples
This document contains examples of Fly.io token attenuation. Each example is a
JSON object that can be used with the "flyctl tokens attenuate" command. For
example, copy the desired caveats to "caveats.json" and run:

"""sh
FLY_API_TOKEN=$(fly tokens org personal) flyctl tokens attenuate -f caveats.json
""""

The "fly tokens org personal" part generates a base token for the "personal"
organization that the caveats from "caveats.json" will be appended to.
`), `"`, "`")

var examples = exampleSlice{
	{
		name:        "App Read-Only",
		description: "Allow the token to do nothing but read the specified app. This includes app-owned resources like logs, certificates, etc.. The app IDs are the app's internal database IDs, which can be found via the GraphQL API.",
		cavs: caveatSlice{
			&flyio.Apps{Apps: resset.New[uint64](resset.ActionRead, 123, 234)},
		},
	},
	{
		name:        "Allowlist GraphQL Mutations",
		description: "Allow the token to do nothing but execute the specified GraphQL mutations.",
		cavs: caveatSlice{
			&flyio.Mutations{Mutations: []string{"addCertificate"}},
		},
	},
}

func main() {
	f, err := os.Create("README.md")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, strings.TrimSpace(header+"\n%s"), examples); err != nil {
		panic(err)
	}
}

type exampleSlice []example

func (e exampleSlice) String() string {
	strs := make([]string, len(e))
	for _, ex := range e {
		strs = append(strs, ex.String())
	}
	return strings.Join(strs, "\n")
}

type example struct {
	name        string
	description string
	cavs        caveatSlice
}

func (e example) String() string {
	return fmt.Sprintf("## %s\n%s\n%s", e.name, e.description, e.cavs)
}

type caveatSlice []macaroon.Caveat

func (c caveatSlice) String() string {
	buf := new(bytes.Buffer)
	je := json.NewEncoder(buf)
	je.SetIndent("", "  ")
	if err := je.Encode(macaroon.NewCaveatSet(c...)); err != nil {
		panic(err)
	}
	return fmt.Sprintf("```json\n%s```", buf.String())
}
