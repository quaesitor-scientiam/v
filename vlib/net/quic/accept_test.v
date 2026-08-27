// vtest build: present_openssl?
module quic

import crypto.ecdsa
import encoding.base64

// accept_test_cert_pem is a REAL, freshly-generated (openssl ecparam +
// openssl req -x509, this session), self-signed P-256 certificate for
// CN=localhost / SAN=DNS:localhost, WITH a critical CA:TRUE basic
// constraint -- unlike chain_test_cert_pem/conn_test_cert_pem (this same
// module's other test certs, both deliberately lacking CA:TRUE to test the
// REJECTION path), this one is built specifically so a real client can use
// it as its OWN trust anchor and have verify_server_certificate_chain
// actually SUCCEED. This is what lets the test below drive the ENTIRE real
// dial()/accept() flow -- including Certificate/CertificateVerify chain
// verification -- rather than bypassing it the way conn_test.v's own
// white-box tests do (injecting a synthetic VerifiedCertificateChain
// directly), closing the one gap 13a's own PROGRESS.md notes left open
// ("Certificate/CertificateVerify chain verification is not exercised
// end-to-end (no EC certificate fixture in this repo)").
const accept_test_cert_pem = '-----BEGIN CERTIFICATE-----\nMIIBpTCCAUugAwIBAgIUetSYX9TDsFKNHR+Zy05VdXcp+1cwCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDgyNDIyNTkyMloYDzIxMjYwNzMx\nMjI1OTIyWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAAS6mM0J/l1Y65oZMLxYPHvySK8RJbkuECLMXmF3+yeIdqH9cCtKqumw\nDpY+Kz9IjfoVcqdyH5DPE5i7aquc1pwno3kwdzAdBgNVHQ4EFgQU/r32o4XKdpEk\nhx2iVbRtvYuVsXswHwYDVR0jBBgwFoAU/r32o4XKdpEkhx2iVbRtvYuVsXswDwYD\nVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQwFAYDVR0RBA0wC4IJbG9jYWxo\nb3N0MAoGCCqGSM49BAMCA0gAMEUCIGVFw0ddsmDoAyFGVy/K+MlbKnboWRZ0ibkM\n1lLBebL2AiEAvXkEh3aKEztQlrTJwIfjjO7l488gaFTZi63ZuWDIkWY=\n-----END CERTIFICATE-----\n'

// accept_test_key_seed is the raw 32-byte private scalar (big-endian, SEC1
// convention -- BN_bin2bn's own expected format, see
// crypto.ecdsa.evpkey_from_seed) of accept_test_cert_pem's matching P-256
// private key, extracted via `openssl ec -text` from the same key that
// signed the certificate above. Feeding this into
// ecdsa.new_key_from_seed reconstructs the EXACT key pair whose public
// half is embedded in the certificate -- required for
// encode_certificate_verify's signature to actually validate against it.
const accept_test_key_seed = [
	u8(0x4f),
	0xd6,
	0x31,
	0x08,
	0x03,
	0xcb,
	0xd1,
	0x42,
	0xd5,
	0xc5,
	0xac,
	0xe4,
	0xd1,
	0xb1,
	0xca,
	0x06,
	0xfb,
	0xde,
	0xc0,
	0x5a,
	0xc0,
	0x6e,
	0xb9,
	0x58,
	0x60,
	0x01,
	0x3f,
	0x02,
	0x79,
	0x7c,
	0xb3,
	0x15,
]

fn accept_test_pem_to_der(pem string) []u8 {
	body :=
		pem.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '').trim_space()
	return base64.decode(body)
}

fn accept_test_transport_parameters() QuicTransportParameters {
	return QuicTransportParameters{
		max_idle_timeout:                    30000
		initial_max_data:                    1 << 20
		initial_max_stream_data_bidi_local:  1 << 16
		initial_max_stream_data_bidi_remote: 1 << 16
		initial_max_streams_bidi:            4
		initial_max_streams_uni:             4
	}
}

// test_dial_and_accept_full_handshake_and_stream_exchange is 13d-1's own
// "real client-vs-server integration test," one layer up from
// tls13_server_handshake_test.v's identically-named TLS-only version: two
// genuine, independently-constructed QuicConn objects (one via dial(), one
// via accept()) drive each other's real poll() through a full RFC 9000
// handshake AND a real application-data stream exchange, with actual UDP
// datagram bytes as the only channel between them (this test never reaches
// into either connection's internals to shortcut anything) -- proving the
// role-aware key selection (own/peer_*_keys), the server's handshake
// bootstrap (dispatch_handshake_message's server branch), and the server's
// HANDSHAKE_DONE send/client's receipt all genuinely agree end to end, not
// merely that each side is internally consistent.
fn test_dial_and_accept_full_handshake_and_stream_exchange() {
	mut signing_key := ecdsa.new_key_from_seed(accept_test_key_seed, fixed_size: true)!
	defer {
		signing_key.free()
	}

	dial_params := DialParams{
		server_name:          'localhost'
		ca_bundle_pem:        accept_test_cert_pem
		alpn_protocols:       ['h3']
		transport_parameters: accept_test_transport_parameters()
	}
	mut client, client_dg := dial(dial_params, 0)!
	mut client_hs := client.client_handshake()
	defer {
		client_hs.free()
	}

	accept_params := AcceptParams{
		transport_parameters: accept_test_transport_parameters()
		alpn_protocols:       ['h3']
		certificate_chain:    [
			CertificateEntry{
				cert_data: accept_test_pem_to_der(accept_test_cert_pem)
			},
		]
		signing_key:          signing_key
	}
	mut server, mut server_result := accept(client_dg.bytes, accept_params, 0)!
	defer {
		if mut sh := server.server_handshake {
			sh.free()
		}
	}

	// Regression check for a bug 13d-1's own adversarial review found: this
	// single accept() call both processes the ClientHello AND flushes the
	// server's own Handshake-space response flight (ServerHello is
	// Initial-space and unaffected, but EncryptedExtensions/Certificate/
	// CertificateVerify/Finished go out via build_handshake_packet in the
	// very same call) -- a naive send-based Initial-key-discard trigger
	// (RFC 9001 §4.9.1 is send-based for the CLIENT, receive-based for the
	// SERVER) would therefore discard the server's Initial keys here,
	// before the client has sent anything back. That silently drops any
	// ClientHello retransmission (ordinary client-side PTO/loss handling)
	// and leaves the server unable to PTO-retransmit its own lost first
	// flight either, stalling the handshake to idle timeout -- a failure
	// mode this test's own lossless, single-round-trip datagram exchange
	// below can never otherwise expose.
	assert !server.initial_keys_discarded

	// Drive the two connections against each other, feeding each side's
	// outgoing datagrams into the other's poll(), until neither produces
	// anything more to send. Bounded (not a `for true`) so a genuine
	// protocol disagreement between the two independently-written roles
	// fails this test with an assertion, not a hang.
	mut client_outgoing := []QuicDatagram{}
	mut server_outgoing := server_result.outgoing.clone()
	mut now := u64(0)
	mut rounds := 0
	for (client_outgoing.len > 0 || server_outgoing.len > 0) && rounds < 20 {
		rounds += 1
		now += 10
		mut next_client_outgoing := []QuicDatagram{}
		mut next_server_outgoing := []QuicDatagram{}
		for dg in server_outgoing {
			r := client.poll(dg.bytes, now)!
			next_client_outgoing << r.outgoing
		}
		for dg in client_outgoing {
			r := server.poll(dg.bytes, now)!
			next_server_outgoing << r.outgoing
		}
		client_outgoing = next_client_outgoing.clone()
		server_outgoing = next_server_outgoing.clone()
	}
	assert rounds < 20, 'handshake did not converge within 20 rounds'

	assert client.state() == .established
	assert server.state() == .established
	// The receive-side mirror of the check above: once the round trip has
	// actually delivered the client's Handshake-space Finished to the
	// server, the new receive-based trigger in process_initial_or_handshake
	// must have fired.
	assert server.initial_keys_discarded
	assert client.negotiated_alpn()? == 'h3'
	assert server.negotiated_alpn()? == 'h3'

	// Application-data round trip: client opens a bidi stream and writes,
	// server reads it and replies on the same stream, client reads the
	// reply -- proving 1-RTT keys, CRYPTO-independent stream framing, and
	// flow control all work correctly on a server-role connection, not
	// just the handshake itself.
	stream_id := client.open_stream(true)!
	client.write_stream(stream_id, 'hello from client'.bytes(), false)!

	now += 10
	mut client_to_server := client.poll(none, now)!
	assert client_to_server.outgoing.len > 0

	mut server_read := []u8{}
	server_outgoing = []QuicDatagram{}
	for dg in client_to_server.outgoing {
		r := server.poll(dg.bytes, now)!
		server_outgoing << r.outgoing
		if data := server.read_stream(stream_id) {
			server_read << data
		}
	}
	assert server_read.bytestr() == 'hello from client'

	server.write_stream(stream_id, 'hello from server'.bytes(), true)!
	now += 10
	server_result = server.poll(none, now)!
	server_outgoing << server_result.outgoing
	assert server_outgoing.len > 0

	mut client_read := []u8{}
	for dg in server_outgoing {
		client.poll(dg.bytes, now)!
		if data := client.read_stream(stream_id) {
			client_read << data
		}
	}
	assert client_read.bytestr() == 'hello from server'
}

// test_accept_rejects_undersized_initial_datagram is a regression test for
// RFC 9000 §14.1's anti-amplification floor, a gap 13d-1's own adversarial
// review found: accept() never checked the incoming datagram's length
// before deriving keys and queuing a full ServerHello+EncryptedExtensions+
// Certificate+CertificateVerify+Finished response flight -- letting an
// attacker trigger a large response from a small, address-spoofed
// datagram. Uses a real dial()-produced ClientHello datagram (so the
// Initial packet itself is well-formed and would otherwise be accepted),
// truncated below the 1200-byte floor, to isolate the length check from
// every other rejection reason accept() might have.
fn test_accept_rejects_undersized_initial_datagram() {
	dial_params := DialParams{
		server_name:          'localhost'
		ca_bundle_pem:        accept_test_cert_pem
		alpn_protocols:       ['h3']
		transport_parameters: accept_test_transport_parameters()
	}
	mut client, client_dg := dial(dial_params, 0)!
	mut client_hs := client.client_handshake()
	defer {
		client_hs.free()
	}
	assert client_dg.bytes.len >= min_initial_datagram_size

	mut signing_key := ecdsa.new_key_from_seed(accept_test_key_seed, fixed_size: true)!
	defer {
		signing_key.free()
	}
	accept_params := AcceptParams{
		transport_parameters: accept_test_transport_parameters()
		alpn_protocols:       ['h3']
		certificate_chain:    [
			CertificateEntry{
				cert_data: accept_test_pem_to_der(accept_test_cert_pem)
			},
		]
		signing_key:          signing_key
	}
	truncated := client_dg.bytes[..min_initial_datagram_size - 1].clone()
	accept(truncated, accept_params, 0) or {
		assert err.msg().contains('smaller than')
		return
	}
	assert false, 'accept() must reject a datagram under the 1200-byte anti-amplification floor'
}

// accept_test_transport_parameters_with_cid_limit is
// accept_test_transport_parameters' own base plus an explicit
// active_connection_id_limit -- the shared helper deliberately leaves it
// unset (so OTHER tests in this file exercise the RFC 9000 §18.2 default of
// 2), but Phase 14b's own real end-to-end test below wants a peer limit
// bigger than 2 to prove the "replenish up to several, not just one more"
// path, not only the degenerate single-extra-CID case.
fn accept_test_transport_parameters_with_cid_limit(limit u64) QuicTransportParameters {
	mut p := accept_test_transport_parameters()
	p.active_connection_id_limit = limit
	return p
}

// test_dial_and_accept_negotiates_active_connection_id_set is Phase 14b's
// own real end-to-end proof, one layer up from
// active_connection_id_set_test.v's pure accounting-type tests and
// conn_test.v's dispatch-level tests (which inject manually-constructed
// frames into ONE side): two genuine, independently-constructed QuicConn
// objects drive each other through a full handshake with actual UDP
// datagram bytes as the only channel between them, each side's own
// NEW_CONNECTION_ID frames arriving at and being correctly processed by the
// OTHER side's real dispatch_one_rtt_frame -- not merely that each side's
// bookkeeping is internally self-consistent (the same rationale
// test_dial_and_accept_full_handshake_and_stream_exchange's own doc comment
// gives for existing at all, applied to this phase's own new surface).
fn test_dial_and_accept_negotiates_active_connection_id_set() {
	mut signing_key := ecdsa.new_key_from_seed(accept_test_key_seed, fixed_size: true)!
	defer {
		signing_key.free()
	}

	dial_params := DialParams{
		server_name:          'localhost'
		ca_bundle_pem:        accept_test_cert_pem
		alpn_protocols:       ['h3']
		transport_parameters: accept_test_transport_parameters_with_cid_limit(4)
	}
	mut client, client_dg := dial(dial_params, 0)!
	mut client_hs := client.client_handshake()
	defer {
		client_hs.free()
	}

	accept_params := AcceptParams{
		transport_parameters: accept_test_transport_parameters_with_cid_limit(4)
		alpn_protocols:       ['h3']
		certificate_chain:    [
			CertificateEntry{
				cert_data: accept_test_pem_to_der(accept_test_cert_pem)
			},
		]
		signing_key:          signing_key
	}
	mut server, mut server_result := accept(client_dg.bytes, accept_params, 0)!
	defer {
		if mut sh := server.server_handshake {
			sh.free()
		}
	}

	// Same bounded pump-until-quiet shape as
	// test_dial_and_accept_full_handshake_and_stream_exchange -- CID
	// issuance rides the SAME drain_outgoing/poll() cycle as the handshake
	// itself (drain_pending_new_connection_ids fires alongside
	// drain_flow_control_raises, both gated on app_write_keys existing),
	// so no separate driving step is needed for it to converge here too.
	mut client_outgoing := []QuicDatagram{}
	mut server_outgoing := server_result.outgoing.clone()
	mut now := u64(0)
	mut rounds := 0
	for (client_outgoing.len > 0 || server_outgoing.len > 0) && rounds < 20 {
		rounds += 1
		now += 10
		mut next_client_outgoing := []QuicDatagram{}
		mut next_server_outgoing := []QuicDatagram{}
		for dg in server_outgoing {
			r := client.poll(dg.bytes, now)!
			next_client_outgoing << r.outgoing
		}
		for dg in client_outgoing {
			r := server.poll(dg.bytes, now)!
			next_server_outgoing << r.outgoing
		}
		client_outgoing = next_client_outgoing.clone()
		server_outgoing = next_server_outgoing.clone()
	}
	assert rounds < 20, 'handshake + CID negotiation did not converge within 20 rounds'
	assert client.state() == .established
	assert server.state() == .established

	// Each side's OWN issued set reaches the OTHER's advertised limit (4):
	// sequence 0 (the seed) plus 3 more via drain_pending_new_connection_ids.
	assert client.local_cid_set.active_count() == 4
	assert server.local_cid_set.active_count() == 4

	// Each side's PEER set mirrors what the other actually issued -- the
	// real proof this isn't just "each side thinks it sent 3 frames," but
	// that the wire round trip and the receiving side's
	// dispatch_one_rtt_frame/note_new_connection_id path genuinely landed
	// all of them.
	assert client.peer_cid_set.active_count() == 4
	assert server.peer_cid_set.active_count() == 4

	// Every locally-issued CID's stateless_reset_token was also correctly
	// carried across the wire and recorded on the receiving side's
	// StatelessResetTracker (not just counted) -- spot-check one non-seed
	// entry each way.
	client_issued_seq1 := client.local_cid_set.entries[u64(1)] or {
		panic('client must have issued sequence 1')
	}
	assert server.stateless_reset.is_stateless_reset(client_issued_seq1.connection_id,
		client_issued_seq1.stateless_reset_token)
	server_issued_seq1 := server.local_cid_set.entries[u64(1)] or {
		panic('server must have issued sequence 1')
	}
	assert client.stateless_reset.is_stateless_reset(server_issued_seq1.connection_id,
		server_issued_seq1.stateless_reset_token)
}
