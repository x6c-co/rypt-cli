package cli

import "strings"

// options holds the parsed command line of encrypt or decrypt.
type options struct {
	keyID     string
	keyIDSet  bool
	output    string
	outputSet bool
	force     bool
	cipher    string
	cipherSet bool
	label     string
	labelSet  bool
	help      bool
	input     string // "" or "-" means stdin
}

// parseArgs parses the arguments of encrypt or decrypt. Flags and the FILE
// argument may appear in any order; "--" ends the flags. A value flag takes
// its value from the next argument or after "=", as in --output=PATH.
func parseArgs(cmd string, args []string) (*options, error) {
	o := &options{}
	inputSet := false
	setInput := func(a string) error {
		if inputSet {
			return usageErrorf("%s takes at most one FILE argument", cmd)
		}
		if a == "" {
			return usageErrorf("the FILE argument is empty")
		}
		o.input, inputSet = a, true
		return nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, rest := range args[i+1:] {
				if err := setInput(rest); err != nil {
					return nil, err
				}
			}
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			if err := setInput(a); err != nil {
				return nil, err
			}
			continue
		}

		name, value, hasValue := a, "", false
		if strings.HasPrefix(a, "--") {
			name, value, hasValue = strings.Cut(a, "=")
		}
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", usageErrorf("flag %s needs a value", name)
			}
			i++
			return args[i], nil
		}

		var err error
		switch name {
		case "-k", "--key-id":
			o.keyID, err = takeValue()
			o.keyIDSet = true
		case "-o", "--output":
			o.output, err = takeValue()
			o.outputSet = true
		case "-f", "--force":
			if hasValue {
				return nil, usageErrorf("flag %s does not take a value", name)
			}
			o.force = true
		case "--cipher":
			o.cipher, err = takeValue()
			o.cipherSet = true
		case "--label":
			o.label, err = takeValue()
			o.labelSet = true
		case "-h", "--help":
			if hasValue {
				return nil, usageErrorf("flag %s does not take a value", name)
			}
			o.help = true
		default:
			return nil, usageErrorf("unknown flag %s", name)
		}
		if err != nil {
			return nil, err
		}
	}

	if cmd == "decrypt" {
		// decrypt takes the key ID from the file header and ignores --key-id.
		if o.cipherSet {
			return nil, usageErrorf("--cipher applies to encrypt only")
		}
		if o.labelSet {
			return nil, usageErrorf("--label applies to encrypt only; decrypt reads the label from the file header")
		}
	}
	if o.outputSet && o.output == "" {
		return nil, usageErrorf("the output path is empty")
	}
	return o, nil
}
