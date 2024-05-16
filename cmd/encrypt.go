package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"go.starlark.net/starlark"

	"tidbyt.dev/pixlet/runtime"

	"tidbyt.dev/pixlet/manifest"
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

var EncryptCmd = &cobra.Command{
	Use:     "encrypt [secret value]",
	Short:   "Encrypt a secret for use in the Tidbyt community repo",
	Long:    "Encrypt a secret for use in the Tidbyt community repo. Invoke this from the same folder as your app.",
	Example: "encrypt my-top-secretweather-api-key-123456",
	Args:    cobra.MinimumNArgs(1),
	Run:     encrypt,
}

func encrypt(cmd *cobra.Command, args []string) {
	sek := &runtime.SecretEncryptionKey{
		PublicKeysetJSON: []byte(PublicKeysetJSON),
	}

	if len(args) == 1 {
		// find the manifest file, must be in same directory
		reader, err := os.Open(manifest.ManifestFileName)
		if err != nil {
			log.Fatalf("Could not open manifest file. Are you in the same folder as your app? Error: %v", err)
		}

		// deserialize
		m, err := manifest.LoadManifest(reader)
		if err != nil {
			log.Fatalf("error deserializing manifest.yaml: %v", err)
		}

		// encrypt it using the app ID we found in the manifest
		encrypted, err := sek.Encrypt(m.ID, args[0])
		if err != nil {
			log.Fatalf("error encrypting value: %v", err)
		}
		// print the encrypted values formatted for pasting into starlark file
		fmt.Println(starlark.String(encrypted).String())
	} else {
		// if they passed more than a single arg it means they are specifying app ID
		appID := args[0]
		encrypted := make([]string, len(args)-1)

		// encrypt each value they passed separately
		for i, val := range args[1:] {
			var err error
			encrypted[i], err = sek.Encrypt(appID, val)
			if err != nil {
				log.Fatalf("error encrypting value: %v", err)
			}
		}

		// print the encrypted values formatted for pasting into starlark file
		for _, val := range encrypted {
			fmt.Println(starlark.String(val).String())
		}
	}
}
