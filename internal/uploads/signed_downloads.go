package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	signature := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	result, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, result)
	mac_signature := mac.Sum(nil)

	providedBytes, err1 := hex.DecodeString(signature)
	if err1 != nil {
		return false
	}
	if result <= now.Unix() {
		return false
	}
	return subtle.ConstantTimeCompare(providedBytes, mac_signature) == 1
}
