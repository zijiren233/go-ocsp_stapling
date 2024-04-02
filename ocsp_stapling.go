package ocsp_stapling

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

type OcspHandler struct {
	crt            *tls.Certificate
	isRevoked      bool
	ocspNextUpdate time.Time
	leaf, issuer   *x509.Certificate
	client         *http.Client
	lastErr        atomic.Value
	ctx            context.Context
	cancel         context.CancelFunc
}

func (h *OcspHandler) getResponse(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ocspReq, err := ocsp.CreateRequest(h.leaf, h.issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ocsp request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.leaf.OCSPServer[0], bytes.NewBuffer(ocspReq))
	if err != nil {
		return nil, fmt.Errorf("failed to create ocsp request: %w", err)
	}
	httpReq.Header.Add("Content-Language", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-response")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send ocsp request: %w", err)
	}
	defer resp.Body.Close()

	barOcspResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read ocsp response: %w", err)
	}

	ocspRes, err := ocsp.ParseResponse(barOcspResp, h.issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ocsp response: %w", err)
	}

	h.isRevoked = ocspRes.Status == ocsp.Revoked
	if ocspRes.Status == ocsp.Good {
		h.ocspNextUpdate = ocspRes.NextUpdate
		return barOcspResp, nil
	} else {
		h.ocspNextUpdate = time.Now().Add(5 * time.Minute)
		return nil, fmt.Errorf("ocsp response status is %d", ocspRes.Status)
	}
}

func (h *OcspHandler) Start() {
	go h.Run()
}

func (h *OcspHandler) Stop() {
	h.cancel()
}

func (h *OcspHandler) Run() {
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
			res, err := h.getResponse(h.ctx)
			if err != nil {
				h.lastErr.Store(err)
			}

			if h.isRevoked {
				break
			}

			if len(res) != 0 {
				h.crt.OCSPStaple = res
			}

			time.Sleep(time.Until(h.ocspNextUpdate))
		}
	}
}

type OcspHandlerOption func(*OcspHandler)

func WithHttpClient(client *http.Client) OcspHandlerOption {
	return func(h *OcspHandler) {
		h.client = client
	}
}

func WithContext(ctx context.Context) OcspHandlerOption {
	return func(h *OcspHandler) {
		h.ctx = ctx
	}
}

func NewOcspHandler(crt *tls.Certificate, opts ...OcspHandlerOption) (*OcspHandler, error) {
	if crt == nil {
		return nil, errors.New("crt is nil")
	}
	if len(crt.Certificate) < 2 {
		return nil, errors.New("no issuer in chain")
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, err
	}
	issuer, err := x509.ParseCertificate(crt.Certificate[1])
	if err != nil {
		return nil, err
	}

	// Check if the issuer is actually the issuer of the leaf certificate.
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		// If not, swap the leaf and the issuer.
		leaf, issuer = issuer, leaf
	}

	oh := &OcspHandler{
		crt:    crt,
		leaf:   leaf,
		issuer: issuer,
		client: &http.Client{},
		ctx:    context.Background(),
	}

	for _, opt := range opts {
		opt(oh)
	}

	oh.ctx, oh.cancel = context.WithCancel(oh.ctx)

	return oh, nil
}

func (h *OcspHandler) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return h.crt, nil
}

func (h *OcspHandler) LastError() error {
	if err := h.lastErr.Load(); err != nil {
		return err.(error)
	}
	return nil
}
