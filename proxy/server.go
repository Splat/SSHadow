package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"SSHadow/monitor"

	"golang.org/x/crypto/ssh"
)

// Server represents the SSH proxy server
type Server struct {
	listenAddr string
	targetAddr string
	config     *ssh.ServerConfig
	tracker    *monitor.Tracker
	authCache  sync.Map // Store auth details temporarily
}

type authDetails struct {
	authType    monitor.AuthType
	pubKey      ssh.PublicKey
	password    string
	fingerprint string
}

// NewServer creates a new SSH proxy server
func NewServer(listenAddr, targetAddr, hostKeyPath string, tracker *monitor.Tracker) (*Server, error) {
	// Load host private key
	privateBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %w", err)
	}

	srv := &Server{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		tracker:    tracker,
	}

	// Configure SSH server
	srv.config = &ssh.ServerConfig{
		PublicKeyCallback: srv.publicKeyCallback,
		PasswordCallback:  srv.passwordCallback,
		NoClientAuth:      false,
	}
	srv.config.AddHostKey(private)

	return srv, nil
}

// publicKeyCallback handles public key and certificate authentication
func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	sessionID := string(conn.SessionID())
	authType := monitor.AuthPublicKey

	// Check if it's a certificate
	if _, ok := key.(*ssh.Certificate); ok {
		authType = monitor.AuthCert
	}

	// Calculate fingerprint
	fingerprint := ssh.FingerprintSHA256(key)

	s.authCache.Store(sessionID, &authDetails{
		authType:    authType,
		pubKey:      key,
		fingerprint: fingerprint,
	})

	// Accept all keys - actual auth happens at the target server
	return &ssh.Permissions{
		Extensions: map[string]string{
			"auth_type": string(authType),
		},
	}, nil
}

// passwordCallback handles password authentication
func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	sessionID := string(conn.SessionID())
	s.authCache.Store(sessionID, &authDetails{
		authType: monitor.AuthPassword,
		password: string(password),
	})

	// Accept all passwords - actual auth happens at the target server
	return &ssh.Permissions{
		Extensions: map[string]string{
			"auth_type": string(monitor.AuthPassword),
		},
	}, nil
}

// ListenAndServe starts the proxy server
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	// Handle shutdown
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go s.handleConnection(tcpConn)
	}
}

// handleConnection handles a single SSH connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(clientConn, s.config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	// Extract connection metadata
	sourceIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	username := sshConn.User()
	sessionID := string(sshConn.SessionID())

	// Get auth details from cache
	var pubKey ssh.PublicKey
	var authType monitor.AuthType = monitor.AuthPassword
	var password string
	var fingerprint string

	if cached, ok := s.authCache.Load(sessionID); ok {
		details := cached.(*authDetails)
		authType = details.authType
		pubKey = details.pubKey
		password = details.password
		fingerprint = details.fingerprint
		s.authCache.Delete(sessionID)
	}

	// Generate connection ID
	connID := fmt.Sprintf("proxy-%s-%s-%x", sourceIP, username, sshConn.SessionID()[:8])

	// Register connection with tracker
	s.tracker.AddConnectionFromProxy(connID, sourceIP, username, authType, pubKey, fingerprint)
	defer s.tracker.RemoveConnection(connID)

	log.Printf("[proxy] New connection: %s@%s (auth: %s)", username, sourceIP, authType)

	// Connect to target SSH server
	targetConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            s.buildAuthMethods(password),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, verify host key
	}

	targetConn, err := ssh.Dial("tcp", s.targetAddr, targetConfig)
	if err != nil {
		log.Printf("[proxy] Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	// Proxy channels and requests
	var wg sync.WaitGroup

	// Handle incoming channel requests from client
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newChannel := range chans {
			s.handleChannel(newChannel, targetConn, connID)
		}
	}()

	// Handle global requests from client
	wg.Add(1)
	go func() {
		defer wg.Done()
		ssh.DiscardRequests(reqs)
	}()

	wg.Wait()
	log.Printf("[proxy] Connection closed: %s@%s", username, sourceIP)
}

// buildAuthMethods creates auth methods for connecting to the target server
func (s *Server) buildAuthMethods(password string) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	// Password auth can be forwarded
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}

	// Note: Public key/certificate auth cannot be forwarded without the private key
	// or SSH agent forwarding (-A). This is a known limitation.
	// Future enhancement: Support SSH agent forwarding for pubkey/cert auth.

	return methods
}

// handleChannel proxies a single SSH channel
func (s *Server) handleChannel(newChannel ssh.NewChannel, targetConn *ssh.Client, connID string) {
	s.tracker.UpdateActivity(connID)

	// Open corresponding channel on target
	targetChan, targetReqs, err := targetConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("target open failed: %v", err))
		return
	}
	defer targetChan.Close()

	// Accept the channel from client
	clientChan, clientReqs, err := newChannel.Accept()
	if err != nil {
		log.Printf("[proxy] Channel accept failed: %v", err)
		return
	}
	defer clientChan.Close()

	// Proxy requests bidirectionally
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.proxyRequests(clientReqs, targetChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.proxyRequests(targetReqs, clientChan)
	}()

	// Proxy data bidirectionally
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetChan, clientChan)
		targetChan.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientChan, targetChan)
		clientChan.CloseWrite()
	}()

	wg.Wait()
}

// proxyRequests forwards SSH requests from one channel to another
func (s *Server) proxyRequests(reqs <-chan *ssh.Request, channel ssh.Channel) {
	for req := range reqs {
		ok, err := channel.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok, nil)
		}
		if err != nil {
			return
		}
	}
}
