/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugins

import (
	"fmt"
	"strings"

	"k8s.io/test-infra/prow/github"
)

const AboutThisBotWithoutCommands = ""
const AboutThisBotCommands = "I understand the commands that are listed [here](https://go.k8s.io/bot-commands)."
const AboutThisBot = AboutThisBotWithoutCommands + " " + AboutThisBotCommands

// FormatResponse nicely formats a response to a generic reason.
func FormatResponse(to, message, reason string) string {
	format := `@%s: %s

<details>

%s

%s
</details>`

	return fmt.Sprintf(format, to, message, reason, AboutThisBotWithoutCommands)
}

// FormatSimpleResponse formats a response that does not warrant additional explanation in the
// details section.
func FormatSimpleResponse(to, message string) string {
	format := `@%s: %s

<details>

%s
</details>`

	return fmt.Sprintf(format, to, message, AboutThisBotWithoutCommands)
}

// FormatICResponse nicely formats a response to an issue comment.
func FormatICResponse(ic github.IssueComment, s string) string {
	return FormatResponseRaw(ic.Body, ic.HTMLURL, ic.User.Login, s)
}

// FormatResponseRaw nicely formats a response for one does not have an issue comment
func FormatResponseRaw(body, bodyURL, login, reply string) string {
	format := `In response to [this](%s):

%s
`
	// Quote the user's comment by prepending ">" to each line.
	var quoted []string
	for _, l := range strings.Split(body, "\n") {
		quoted = append(quoted, ">"+l)
	}
	return FormatResponse(login, reply, fmt.Sprintf(format, bodyURL, strings.Join(quoted, "\n")))
}
