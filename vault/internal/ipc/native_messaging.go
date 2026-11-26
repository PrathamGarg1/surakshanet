package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxNativeMessageSize = 1024 * 1024 // Chrome Native Messaging limit (1 MB host->ext, 4 GB ext->host)

// ReadNativeMessage reads one Chrome Native Messaging frame (uint32 LE length + JSON body).
func ReadNativeMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 || length > 4*1024*1024 {
		return nil, fmt.Errorf("invalid native message length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteNativeMessage writes one Chrome Native Messaging frame (uint32 LE length + JSON body).
func WriteNativeMessage(w io.Writer, payload []byte) error {
	if len(payload) > maxNativeMessageSize {
		return fmt.Errorf("native response exceeds %d bytes", maxNativeMessageSize)
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// RunNativeBridge loops on Chrome's stdin/stdout Native Messaging stream,
// forwarding each request to the privileged Vault Daemon over local IPC.
func RunNativeBridge(r io.Reader, w io.Writer, network, address string) error {
	for {
		raw, err := ReadNativeMessage(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		var req Request
		var resp *Response
		if err := json.Unmarshal(raw, &req); err != nil {
			resp = &Response{OK: false, Error: "invalid native request JSON: " + err.Error()}
		} else {
			resp, err = SendRequest(network, address, req)
			if err != nil {
				resp = &Response{OK: false, Error: err.Error()}
			}
		}

		encoded, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if err := WriteNativeMessage(w, encoded); err != nil {
			return err
		}
	}
}
