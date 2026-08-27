module quic

// active_connection_id_set.v -- RFC 9000 §5.1's connection ID lifecycle
// bookkeeping (Phase 14b): the two independent connection-ID sets every
// QUIC connection maintains once past the handshake -- the CIDs THIS
// endpoint has issued for the peer to address packets to it with (the
// "local" set), and the CIDs the PEER has issued for THIS endpoint to
// address packets to the peer with (the "peer" set). Deliberately pure,
// standalone, unit-testable structs, mirroring anti_amplification.v's own
// "dumb accounting primitive, caller decides policy" shape -- conn.v wires
// these into the real send/receive path (drain_pending_new_connection_ids,
// the NewConnectionIdFrame/RetireConnectionIdFrame dispatch arms).
//
// Scope note (see PROGRESS.md's Phase 14b entry for the full writeup):
// PeerConnectionIdSet tracks which peer-issued CIDs COULD be migrated to;
// it never itself changes a connection's active outgoing dcid -- deciding
// WHEN/WHETHER to switch is Phase 14c/14e's path-validation state machine,
// not yet built. A THIS-connection's own newly-issued local CIDs ARE
// already accepted for incoming 1-RTT packets (conn.v's
// process_one_rtt_packet checks LocalConnectionIdSet.contains(), not just
// c.scid) -- but for a SERVER specifically, QuicListener demuxes MANY
// concurrent connections by connection ID, and its own routing table is
// still keyed only by each connection's ORIGINAL scid (listener.v);
// registering the REST of a connection's active local CIDs there too, so
// the listener itself can find the right QuicConn for a packet addressed
// to one of them, is Phase 14d's job, not yet built. Until then, a
// server-role connection accepts a packet addressed to a newly-issued
// local CID only if it somehow already reaches THIS connection's own
// poll() call (true for a single-connection-per-socket CLIENT already,
// not yet true for a real multi-connection server behind QuicListener).
// This is a narrower, more precise scope limit than earlier drafts of this
// note stated -- found and fixed during 14b's own /vreview pass, 2026-08-27
// (see [[code-review-misses]]): the FIRST version of this feature also
// rejected such packets at the single-connection level, making the whole
// feature inert even for a client with no listener involved at all.

// quic_error_connection_id_limit is RFC 9000 §20.1's CONNECTION_ID_LIMIT_ERROR.
const quic_error_connection_id_limit = u64(0x09)

// default_active_connection_id_limit is RFC 9000 §18.2's stated default for
// the active_connection_id_limit transport parameter, assumed for a peer
// until (and unless) its own value, if any, is known -- mirrors
// default_ack_delay_exponent's identical role for that parameter (frame.v).
const default_active_connection_id_limit = u64(2)

// LocalConnectionId is one connection ID THIS endpoint has issued to its
// peer via NEW_CONNECTION_ID (RFC 9000 §5.1.1) for the peer to use as ITS
// own outgoing packets' Destination Connection ID when addressing this
// endpoint.
pub struct LocalConnectionId {
pub:
	connection_id         []u8
	stateless_reset_token []u8 // 16 bytes; empty only for sequence 0 -- see LocalConnectionIdSet's own note
}

// LocalConnectionIdSet tracks every CID this endpoint has issued and is
// still willing to have the peer address it by. Sequence 0 is always this
// connection's own original `scid`, established during the handshake with
// no NEW_CONNECTION_ID frame of its own -- seeded by
// new_local_connection_id_set, never re-inserted through issue_next.
pub struct LocalConnectionIdSet {
mut:
	entries  map[u64]LocalConnectionId
	next_seq u64
}

// new_local_connection_id_set seeds the set with this connection's own
// original scid at sequence 0. Its stateless_reset_token is empty today --
// a deliberate, documented gap: neither dial() nor accept() currently
// advertises this endpoint's own stateless_reset_token TRANSPORT PARAMETER
// (RFC 9000 §10.3.1's mechanism for a CID with no NEW_CONNECTION_ID frame
// of its own), unlike every subsequently issued CID, which carries an
// explicit per-frame token generated at issue_next time. Wiring that
// transport parameter needs a stable secret this endpoint can regenerate
// tokens from even after losing per-connection state -- naturally a
// LISTENER-wide secret for the server role (mirroring
// generate_stateless_reset_token's own static_key parameter,
// stateless_reset.v), which doesn't exist yet; flagged, not fixed here,
// the same class of deliberate defer 13b's own dial()-rand gap was.
pub fn new_local_connection_id_set(scid []u8) LocalConnectionIdSet {
	mut s := LocalConnectionIdSet{
		next_seq: 1
	}
	s.entries[u64(0)] = LocalConnectionId{
		connection_id:         scid.clone()
		stateless_reset_token: []u8{}
	}
	return s
}

// active_count reports how many locally-issued CIDs are still active
// (issued and not yet retired by the peer).
pub fn (s &LocalConnectionIdSet) active_count() u64 {
	return u64(s.entries.len)
}

// contains reports whether `cid` is one of this endpoint's own currently
// active connection IDs -- sequence 0's original scid, or any
// not-yet-retired sequence issued via issue_next. Used to accept an
// incoming 1-RTT packet addressed to ANY of this endpoint's valid CIDs, not
// only the original one: RFC 9000 §5.1.1 exists specifically so a peer MAY
// address a packet using any CID this endpoint has issued and not yet
// retired, and rejecting every one but the seed would make issuing them at
// all pointless. Linear scan -- active_count() is bounded by whatever this
// endpoint's own active_connection_id_limit is (typically single digits,
// RFC 9000 §18.2's default is 2), so this is cheap; a lookup structure
// keyed by connection_id would be premature for that size.
pub fn (s &LocalConnectionIdSet) contains(cid []u8) bool {
	for _, entry in s.entries {
		if entry.connection_id == cid {
			return true
		}
	}
	return false
}

// issue_next allocates the next sequence number, storing `connection_id`/
// `stateless_reset_token` under it and returning the sequence number
// assigned -- the caller (conn.v) builds the actual NEW_CONNECTION_ID frame
// from the return value plus the same connection_id/token it passed in.
// Sequence numbers are never reused, even across retirements (RFC 9000
// §5.1.1) -- next_seq only ever increases.
pub fn (mut s LocalConnectionIdSet) issue_next(connection_id []u8, stateless_reset_token []u8) u64 {
	seq := s.next_seq
	s.entries[seq] = LocalConnectionId{
		connection_id:         connection_id.clone()
		stateless_reset_token: stateless_reset_token.clone()
	}
	s.next_seq++
	return seq
}

// retire removes a locally-issued CID once the peer says (via
// RETIRE_CONNECTION_ID) it will stop using it. Errors if `seq` was never
// issued by this endpoint (RFC 9000 §19.16: "Receipt of a
// RETIRE_CONNECTION_ID frame containing a sequence number greater than any
// previously sent... MUST be treated as a connection error of type
// PROTOCOL_VIOLATION") -- idempotent for an ALREADY-retired sequence
// number that WAS legitimately issued at some point, since a peer
// re-sending the same retire is not itself a protocol violation, just a
// no-op here (the entry is simply already absent).
//
// Also refuses to retire the LAST remaining active entry, even a
// legitimately-issued one. RFC 9000 §19.16's own protection here (a
// RETIRE_CONNECTION_ID MUST NOT reference the sequence number of the
// CURRENT packet's own DCID) needs the packet header at frame-dispatch
// time, which conn.v's call chain doesn't plumb through (a documented,
// deliberate 14b scope limit -- see the caller's own doc comment) -- but
// the CONSEQUENCE of skipping that one check is severe enough to guard
// here anyway, structurally: without SOME floor, a peer that retires every
// sequence number in turn (each individual retire legal in isolation, sent
// while addressing this endpoint via whichever sequence isn't the one
// being retired that round) can drive this set to EMPTY, after which
// process_one_rtt_packet's own LocalConnectionIdSet.contains() check
// rejects every future 1-RTT packet as unrecognized -- a connection-level
// DoS this endpoint inflicts on itself by honoring the request literally.
// Refusing once exactly one entry remains is a broader, simpler version of
// the same protection RFC 9000 §19.16 intends (an endpoint must always
// stay reachable by at least one valid CID), even though it isn't the
// EXACT per-packet check the RFC text describes.
pub fn (mut s LocalConnectionIdSet) retire(seq u64) ! {
	if seq >= s.next_seq {
		return error_with_code('quic: RETIRE_CONNECTION_ID references sequence number ${seq}, never issued by this endpoint (highest issued: ${s.next_seq - 1}) (RFC 9000 §19.16 PROTOCOL_VIOLATION)',
			int(quic_error_protocol_violation))
	}
	// Only a genuine removal (seq currently present) can shrink the set --
	// an idempotent retire of an already-absent-but-legitimately-issued
	// sequence must stay a no-op regardless of the current count, matching
	// this function's own doc comment.
	if seq in s.entries && s.entries.len == 1 {
		return error_with_code('quic: RETIRE_CONNECTION_ID for sequence ${seq} would leave this endpoint with zero active connection IDs, permanently unreachable for future 1-RTT packets (RFC 9000 §19.16 PROTOCOL_VIOLATION)',
			int(quic_error_protocol_violation))
	}
	s.entries.delete(seq)
}

// PeerConnectionId is one connection ID the PEER has issued to THIS
// endpoint via NEW_CONNECTION_ID -- a CID this endpoint could use as its
// own outgoing packets' Destination Connection ID, e.g. once a future
// migration decides to switch paths or rotate for privacy (RFC 9000 §9.5).
pub struct PeerConnectionId {
pub:
	connection_id         []u8
	stateless_reset_token ?[]u8
}

// PeerConnectionIdSet tracks every CID the peer has issued to this
// endpoint that this endpoint is still willing to migrate its own outgoing
// traffic to. Sequence 0 is the CID the peer presented in its own first
// packet of this connection (recorded as `c.dcid` at dial()/accept() time,
// for both roles -- see conn.v's own field doc), with no NEW_CONNECTION_ID
// frame of its own; its token, if any, comes from the peer's
// stateless_reset_token TRANSPORT PARAMETER rather than a frame field.
pub struct PeerConnectionIdSet {
mut:
	entries         map[u64]PeerConnectionId
	retire_prior_to u64 // highest Retire Prior To this endpoint has echoed
}

// new_peer_connection_id_set seeds the set with the peer's own original
// dcid at sequence 0. `stateless_reset_token` is none until (and unless)
// the peer's stateless_reset_token transport parameter arrives -- update
// the sequence-0 entry via set_sequence_zero_token once it does, rather
// than re-seeding the whole set.
//
// Caller note (the two roles reach a TRUE `dcid` at different times): a
// SERVER's peer (the client) presents its real scid immediately, in the
// very first packet accept() processes -- call this once, at construction,
// with that value. A CLIENT's `dcid` starts as its OWN arbitrary
// original_dcid guess, not something the peer ever issued -- dial() must
// call this again (replacing the whole set, not just the sequence-0 entry,
// since nothing else could be valid yet either) once the server's REAL
// scid is confirmed (conn.v's own `c.peer_scid.len == 0` guard, RFC 9000
// §7.2), not at dial()'s own construction time.
pub fn new_peer_connection_id_set(dcid []u8) PeerConnectionIdSet {
	mut s := PeerConnectionIdSet{}
	s.entries[u64(0)] = PeerConnectionId{
		connection_id:         dcid.clone()
		stateless_reset_token: none
	}
	return s
}

// set_sequence_zero_token records the peer's stateless_reset_token
// transport parameter against sequence 0, once it's known (transport
// parameters arrive later in the handshake than dcid itself, which is why
// this is a separate step from new_peer_connection_id_set rather than a
// constructor parameter). A no-op if sequence 0 was already retired via an
// (unusual, but not itself a protocol violation on its own) early
// retire_prior_to bump -- nothing left to attach the token to.
pub fn (mut s PeerConnectionIdSet) set_sequence_zero_token(token []u8) {
	if entry := s.entries[u64(0)] {
		s.entries[u64(0)] = PeerConnectionId{
			connection_id:         entry.connection_id
			stateless_reset_token: token.clone()
		}
	}
}

// active_count reports how many peer-issued CIDs this endpoint currently
// holds (issued and not yet retired).
pub fn (s &PeerConnectionIdSet) active_count() u64 {
	return u64(s.entries.len)
}

// PeerConnectionIdUpdate reports the effect of processing one incoming
// NEW_CONNECTION_ID frame: which sequence numbers must now be retired
// (retire_prior_to advanced past them -- the caller must send a
// RETIRE_CONNECTION_ID for each) and whether this endpoint is now over its
// OWN advertised active_connection_id_limit (RFC 9000 §5.1.1
// CONNECTION_ID_LIMIT_ERROR -- the caller must close the connection).
pub struct PeerConnectionIdUpdate {
pub:
	newly_retired []u64
	over_limit    bool
}

// note_new_connection_id processes one incoming NEW_CONNECTION_ID frame,
// already wire-validated by frame.v's own parse_new_connection_id_frame
// (retire_prior_to <= sequence_number, connection_id 1-20 bytes, token
// exactly 16 bytes). Enforces the two RFC 9000 §19.15/§5.1.1 requirements
// that DO need connection state -- deferred there to the caller, i.e. here:
// rejecting a sequence number already known under a DIFFERENT
// connection_id (a peer MUST NOT reuse a sequence number with a different
// value), and CONNECTION_ID_LIMIT_ERROR, reported via the returned
// PeerConnectionIdUpdate.over_limit rather than an error return --
// actually closing the connection is a caller-level action
// (close_with_error), not something this pure accounting type does itself.
pub fn (mut s PeerConnectionIdSet) note_new_connection_id(seq u64, retire_prior_to u64, connection_id []u8, stateless_reset_token []u8, own_active_connection_id_limit u64) !PeerConnectionIdUpdate {
	if existing := s.entries[seq] {
		if existing.connection_id != connection_id {
			return error_with_code('quic: NEW_CONNECTION_ID reuses sequence number ${seq} with a different connection_id than previously seen (RFC 9000 §19.15)',
				int(quic_error_protocol_violation))
		}
		// Identical re-send of an already-known sequence: idempotent, but
		// retire_prior_to may still have advanced -- fall through rather
		// than returning early.
	} else {
		s.entries[seq] = PeerConnectionId{
			connection_id:         connection_id.clone()
			stateless_reset_token: stateless_reset_token.clone()
		}
	}

	mut newly_retired := []u64{}
	if retire_prior_to > s.retire_prior_to {
		for existing_seq in s.entries.keys() {
			if existing_seq < retire_prior_to {
				newly_retired << existing_seq
			}
		}
		for r in newly_retired {
			s.entries.delete(r)
		}
		s.retire_prior_to = retire_prior_to
	}

	return PeerConnectionIdUpdate{
		newly_retired: newly_retired
		over_limit:    u64(s.entries.len) > own_active_connection_id_limit
	}
}
