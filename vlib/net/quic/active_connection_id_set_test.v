module quic

fn test_local_connection_id_set_seeds_sequence_zero() {
	scid := [u8(1), 2, 3, 4, 5, 6, 7, 8]
	s := new_local_connection_id_set(scid)
	assert s.active_count() == 1
}

fn test_local_connection_id_set_contains_seed() {
	scid := [u8(1), 2, 3, 4, 5, 6, 7, 8]
	s := new_local_connection_id_set(scid)
	assert s.contains(scid)
	assert !s.contains([u8(9), 9, 9, 9, 9, 9, 9, 9])
}

fn test_local_connection_id_set_contains_issued_cid() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	cid := [u8(9), 9, 9, 9, 9, 9, 9, 9]
	s.issue_next(cid, []u8{len: 16})
	assert s.contains(cid)
}

fn test_local_connection_id_set_does_not_contain_retired_cid() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	cid := [u8(9), 9, 9, 9, 9, 9, 9, 9]
	seq := s.issue_next(cid, []u8{len: 16})
	s.retire(seq)!
	assert !s.contains(cid)
}

fn test_local_connection_id_set_retire_refuses_to_empty_the_set() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	// Only the seed is active -- retiring it would leave zero, which must
	// be refused (this is the guard, not the "never issued" check: seq 0
	// genuinely was "issued", implicitly, by new_local_connection_id_set).
	s.retire(u64(0)) or {
		assert err.msg().contains('zero active connection IDs')
		assert err.msg().contains('PROTOCOL_VIOLATION')
		assert s.active_count() == 1
		return
	}
	assert false, 'expected retiring the last active local CID to be refused'
}

fn test_local_connection_id_set_retire_allows_emptying_via_two_steps_leaving_one() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	seq := s.issue_next([u8(9), 9, 9, 9, 9, 9, 9, 9], []u8{len: 16})
	assert s.active_count() == 2
	// With two active, retiring one is fine -- only the LAST one is refused.
	s.retire(seq)!
	assert s.active_count() == 1
	// Now retiring the sole remaining one (sequence 0) must be refused.
	s.retire(u64(0)) or {
		assert err.msg().contains('zero active connection IDs')
		return
	}
	assert false, 'expected retiring the last remaining active local CID to be refused'
}

fn test_local_connection_id_set_retire_last_is_still_idempotent_for_already_absent() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	seq := s.issue_next([u8(9), 9, 9, 9, 9, 9, 9, 9], []u8{len: 16})
	s.retire(seq)!
	assert s.active_count() == 1
	// Retiring the ALREADY-absent seq again must stay a no-op (not treated
	// as "would empty the set", since it wouldn't -- nothing left to
	// remove), even though only one entry remains overall.
	s.retire(seq)!
	assert s.active_count() == 1
}

fn test_local_connection_id_set_issue_next_assigns_increasing_sequences() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	seq1 := s.issue_next([u8(9), 9, 9, 9, 9, 9, 9, 9], []u8{len: 16})
	seq2 := s.issue_next([u8(8), 8, 8, 8, 8, 8, 8, 8], []u8{len: 16})
	assert seq1 == 1
	assert seq2 == 2
	assert s.active_count() == 3 // sequence 0 (seed) + the two just issued
}

fn test_local_connection_id_set_retire_shrinks_active_count() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	seq := s.issue_next([u8(9), 9, 9, 9, 9, 9, 9, 9], []u8{len: 16})
	assert s.active_count() == 2
	s.retire(seq)!
	assert s.active_count() == 1
}

fn test_local_connection_id_set_retire_is_idempotent() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	seq := s.issue_next([u8(9), 9, 9, 9, 9, 9, 9, 9], []u8{len: 16})
	s.retire(seq)!
	// Retiring the same, already-retired sequence again must not error --
	// a peer re-sending the same RETIRE_CONNECTION_ID is not itself a
	// protocol violation (RFC 9000 §19.16 only forbids a sequence number
	// ABOVE anything ever issued, not a repeat of an already-processed one).
	s.retire(seq)!
	assert s.active_count() == 1
}

fn test_local_connection_id_set_retire_rejects_never_issued_sequence() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	s.retire(u64(5)) or {
		assert err.msg().contains('never issued')
		assert err.msg().contains('PROTOCOL_VIOLATION')
		return
	}
	assert false, 'expected retiring a never-issued sequence number to be rejected'
}

fn test_local_connection_id_set_sequence_numbers_never_reused() {
	mut s := new_local_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	seq1 := s.issue_next([u8(9), 9, 9, 9, 9, 9, 9, 9], []u8{len: 16})
	s.retire(seq1)!
	seq2 := s.issue_next([u8(8), 8, 8, 8, 8, 8, 8, 8], []u8{len: 16})
	assert seq2 != seq1
	assert seq2 == seq1 + 1
}

fn test_peer_connection_id_set_seeds_sequence_zero() {
	dcid := [u8(1), 2, 3, 4, 5, 6, 7, 8]
	s := new_peer_connection_id_set(dcid)
	assert s.active_count() == 1
}

fn test_peer_connection_id_set_set_sequence_zero_token() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	token := []u8{len: 16, init: 0xab}
	s.set_sequence_zero_token(token)
	entry := s.entries[u64(0)] or { panic('sequence 0 must still be present') }
	tok := entry.stateless_reset_token or { panic('expected a token to be set') }
	assert tok == token
}

fn test_peer_connection_id_set_note_new_connection_id_adds_entry() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	cid := [u8(9), 9, 9, 9, 9, 9, 9, 9]
	token := []u8{len: 16, init: 0xcd}
	update := s.note_new_connection_id(1, 0, cid, token, u64(10))!
	assert s.active_count() == 2
	assert update.newly_retired.len == 0
	assert update.over_limit == false
	entry := s.entries[u64(1)] or { panic('sequence 1 must be present') }
	assert entry.connection_id == cid
}

fn test_peer_connection_id_set_note_new_connection_id_rejects_sequence_reused_with_different_cid() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	token := []u8{len: 16}
	s.note_new_connection_id(1, 0, [u8(9), 9, 9, 9, 9, 9, 9, 9], token, u64(10))!
	s.note_new_connection_id(1, 0, [u8(8), 8, 8, 8, 8, 8, 8, 8], token, u64(10)) or {
		assert err.msg().contains('different connection_id')
		return
	}
	assert false, 'expected reusing a sequence number with a different connection_id to be rejected'
}

fn test_peer_connection_id_set_note_new_connection_id_allows_identical_resend() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	cid := [u8(9), 9, 9, 9, 9, 9, 9, 9]
	token := []u8{len: 16}
	s.note_new_connection_id(1, 0, cid, token, u64(10))!
	// An identical re-send of the same (sequence, connection_id) pair is
	// not itself a protocol violation -- must not error.
	update := s.note_new_connection_id(1, 0, cid, token, u64(10))!
	assert update.over_limit == false
	assert s.active_count() == 2
}

fn test_peer_connection_id_set_retire_prior_to_retires_lower_sequences() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8]) // seq 0
	token := []u8{len: 16}
	s.note_new_connection_id(1, 0, [u8(9), 9, 9, 9, 9, 9, 9, 9], token, u64(10))! // seq 1
	s.note_new_connection_id(2, 0, [u8(8), 8, 8, 8, 8, 8, 8, 8], token, u64(10))! // seq 2
	assert s.active_count() == 3

	// A NEW_CONNECTION_ID for seq 3 that also bumps retire_prior_to to 2
	// must retire seq 0 and seq 1 (both < 2), leaving seq 2 and the new
	// seq 3 active.
	update := s.note_new_connection_id(3, 2, [u8(7), 7, 7, 7, 7, 7, 7, 7], token, u64(10))!
	assert update.newly_retired.len == 2
	assert u64(0) in update.newly_retired
	assert u64(1) in update.newly_retired
	assert s.active_count() == 2 // seq 2 and seq 3
	assert u64(0) !in s.entries
	assert u64(1) !in s.entries
}

fn test_peer_connection_id_set_retire_prior_to_does_not_regress() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	token := []u8{len: 16}
	s.note_new_connection_id(1, 1, [u8(9), 9, 9, 9, 9, 9, 9, 9], token, u64(10))!
	assert s.active_count() == 1 // seq 0 retired by the first bump
	// A LOWER (or equal) retire_prior_to in a later frame must not un-retire
	// anything or re-process already-handled sequences as newly retired.
	update := s.note_new_connection_id(2, 1, [u8(8), 8, 8, 8, 8, 8, 8, 8], token, u64(10))!
	assert update.newly_retired.len == 0
	assert s.active_count() == 2 // seq 1 (kept) + seq 2 (new)
}

fn test_peer_connection_id_set_reports_over_limit() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8]) // seq 0
	token := []u8{len: 16}
	// own_active_connection_id_limit of 1: sequence 0 alone already meets
	// it, so accepting one more MUST report over_limit.
	update := s.note_new_connection_id(1, 0, [u8(9), 9, 9, 9, 9, 9, 9, 9], token, u64(1))!
	assert update.over_limit == true
	assert s.active_count() == 2
}

fn test_peer_connection_id_set_not_over_limit_within_bound() {
	mut s := new_peer_connection_id_set([u8(1), 2, 3, 4, 5, 6, 7, 8])
	token := []u8{len: 16}
	update := s.note_new_connection_id(1, 0, [u8(9), 9, 9, 9, 9, 9, 9, 9], token, u64(2))!
	assert update.over_limit == false
	assert s.active_count() == 2
}
