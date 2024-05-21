package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"go.starlark.net/starlark"

	"tidbyt.dev/pixlet/manifest"
	"tidbyt.dev/pixlet/runtime"
)

const PublicKeysetJSON = `{
  "primaryKeyId": 1589560679,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
        "value": "ElwKBAgCEAMSUhJQCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNDdHJIbWFjQWVhZEtleRISCgYKAggQEBASCAoECAMQEBAgGAEYARogLGtas20og5yP8/g9mCNLNCWTDeLUdcHH7o9fbzouOQoiIBIth4hdVF5A2sztwfW+hNoZ0ht/HNH3dDTEBPW3GXA2",
        "keyMaterialType": "ASYMMETRIC_PUBLIC"
      },
      "status": "ENABLED",
      "keyId": 1589560679,
      "outputPrefixType": "TINK"
    }
  ]
}`

func init() {
	EncryptCmd.Flags().BoolVar(&autoFlag, "auto", false, "automatically look up app ID")
}

var EncryptCmd = &cobra.Command{
	Use:   "encrypt [app ID] [secret value]...",
	Short: "Encrypt a secret for use in the Tidbyt community repo",
	Long: `Encrypt a secret for use in the Tidbyt community repo. 

The 'app ID' argument is found in the manifest.yaml file for your app under the 'id' attribute.`,
	Example: `encrypt weather my-top-secretweather-api-key-123456
encrypt --auto my-top-secret-weather-api-key-123456`,
	Args: cobra.MinimumNArgs(1),
	Run:  encrypt,
}

func encrypt(cmd *cobra.Command, args []string) {
	sek := &runtime.SecretEncryptionKey{
		PublicKeysetJSON: []byte(PublicKeysetJSON),
	}

	starter := 1
	appID := args[0]
	if autoFlag {
		// look up the app ID from the manifest
		starter = 0
		reader, err := os.Open(manifest.ManifestFileName)
		if err != nil {
			log.Fatalf("Unable to open manifest file. When using the '--auto' flag, invoke the encrypt command from your app folder. Error: %v", err)
		}
		m, err := manifest.LoadManifest(reader)
		if err != nil {
			log.Fatalf("Unable to load manifest file. Error: %v", err)
		}
		appID = m.ID
	} else {
		// make sure we have at least two args
		if len(args) < 2 {
			log.Fatal("When not using the '--auto' flag, encrypt requires at least 2 arguments.")
		}
	}

	encrypted := make([]string, len(args)-starter)

	for i, val := range args[starter:] {
		var err error
		encrypted[i], err = sek.Encrypt(appID, val)
		if err != nil {
			log.Fatalf("encrypting value: %v", err)
		}
	}

	for _, val := range encrypted {
		fmt.Println(starlark.String(val).String())
	}
}
