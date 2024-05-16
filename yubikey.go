package yubikey

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"

	"github.com/go-piv/piv-go/piv"
)

// YubiKeyTokenConfig parameters to start Credential based off of TPM RSA Private Key.
type YubiKeyTokenConfig struct {
	Email, KeyId, Audience string
	Pin                    string
}

type yubiKeyTokenSource struct {
	refreshMutex    *sync.Mutex
	email, audience string
	keyId           string
	pin             string
}

// YubiKeyTokenConfig returns a TokenSource for a ServiceAccount where
// the privateKey is sealed within a YubiKey PIV's Signing Slot (9c)
// The TokenSource uses the Yubikey to sign a JWT representing an AccessTokenCredential.
//
// This TokenSource will only create a token while a YubiKey holding the private keys for a Service
// Account is inserted.
//
// https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html
// https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth
// https://medium.com/google-cloud/faster-serviceaccount-authentication-for-google-cloud-platform-apis-f1355abc14b2
// https://godoc.org/golang.org/x/oauth2/google#JWTAccessTokenSourceFromJSON
//
//	Email (string): The service account to get the token for.
//	Audience (string): The audience representing the service the token is valid for.
//	    The audience must match the name of the Service the token is intended for.  See
//	    documentation links above.
//	    (eg. https://pubsub.googleapis.com/google.pubsub.v1.Publisher)
//	Pin (string): The PIN for the YubiKey.
//	KeyId (string): (optional) The private KeyID for the service account key saved to the TPM.
//	    Find the keyId associated with the service account by running:
//	    `gcloud iam service-accounts keys list --iam-account=<email>``
func YubiKeyTokenSource(tokenConfig *YubiKeyTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Email == "" || tokenConfig.Audience == "" || tokenConfig.Pin == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: YubiKeyTokenConfig.Email, Audience and Pin cannot be nil")
	}

	return &yubiKeyTokenSource{
		refreshMutex: &sync.Mutex{},
		email:        tokenConfig.Email,
		audience:     tokenConfig.Audience,
		keyId:        tokenConfig.KeyId,
		pin:          tokenConfig.Pin,
	}, nil

}

func (ts *yubiKeyTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	var strPointer = new(string)
	*strPointer = ts.pin

	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("Unable to open yubikey %v", err)
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey

	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, fmt.Errorf("Could not find yubikey:  %v", err)
			}
			break
		}
	}
	if yk == nil {
		return nil, fmt.Errorf("Yubikey not found Please make sure the key is inserted %v", err)
	}
	defer yk.Close()

	auth := piv.KeyAuth{PIN: ts.pin} //piv.DefaultPIN
	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return nil, fmt.Errorf("Unable to load certificate not found %v", err)
	}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return nil, fmt.Errorf("Unable to load privateKey %v", err)
	}

	rng := rand.Reader
	iat := time.Now()
	exp := iat.Add(time.Hour)

	hdr, err := json.Marshal(&jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     string(ts.keyId),
	})
	if err != nil {
		return nil, fmt.Errorf("google: Unable to marshall JWT Header: %v", err)
	}
	cs, err := json.Marshal(&jws.ClaimSet{
		Iss: ts.email,
		Sub: ts.email,
		Aud: ts.audience,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("google: Unable to marshall JWT ClaimSet: %v", err)
	}

	jwt := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))
	message := []byte(jwt)
	hasher := sha256.New()
	_, err = hasher.Write(message)
	hashed := hasher.Sum(message[:0])

	s, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("expected private key to implement crypto.Signer")
	}

	signature, err := s.Sign(rng, hashed, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("Error from signing from YubiKey: %v\n", err)
	}
	msg := jwt + "." + base64.URLEncoding.EncodeToString([]byte(signature))
	return &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}, nil
}
