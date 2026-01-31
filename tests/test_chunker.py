"""Tests for message chunking and reassembly."""

import time
import pytest

from basemesh.constants import MAX_CHUNK_DATA, MsgType, HEADER_SIZE
from basemesh.chunker import (
    generate_msg_id,
    chunk_payload,
    ReassemblyBuffer,
    ChunkReassembler,
)
from basemesh.protocol import unpack_message


class TestGenerateMsgId:
    def test_range(self):
        for _ in range(100):
            mid = generate_msg_id()
            assert 0 <= mid <= 65535

    def test_randomness(self):
        ids = {generate_msg_id() for _ in range(50)}
        assert len(ids) > 1


class TestChunkPayload:
    def test_empty_data(self):
        chunks = chunk_payload(b"", MsgType.TX_CHUNK, msg_id=1)
        assert len(chunks) == 1
        header, payload = unpack_message(chunks[0])
        assert payload == b""

    def test_small_data(self):
        data = b"hello"
        chunks = chunk_payload(data, MsgType.TX_CHUNK, msg_id=1)
        assert len(chunks) == 1
        header, payload = unpack_message(chunks[0])
        assert payload == data
        assert header.total_chunks == 1

    def test_exact_chunk_size(self):
        data = b"\xab" * MAX_CHUNK_DATA
        chunks = chunk_payload(data, MsgType.TX_CHUNK, msg_id=1)
        assert len(chunks) == 1

    def test_multi_chunk(self):
        data = b"\xab" * (MAX_CHUNK_DATA + 1)
        chunks = chunk_payload(data, MsgType.TX_CHUNK, msg_id=1)
        assert len(chunks) == 2

    def test_three_chunks(self):
        data = b"\xab" * (MAX_CHUNK_DATA * 2 + 50)
        chunks = chunk_payload(data, MsgType.TX_CHUNK, msg_id=1)
        assert len(chunks) == 3

    def test_chunk_numbering(self):
        data = b"\xab" * (MAX_CHUNK_DATA * 3)
        chunks = chunk_payload(data, MsgType.TX_CHUNK, msg_id=1)
        for i, chunk in enumerate(chunks):
            header, _ = unpack_message(chunk)
            assert header.chunk_num == i
            assert header.total_chunks == 3

    def test_reassembles_correctly(self):
        data = b"A" * 300 + b"B" * 200
        chunks = chunk_payload(data, MsgType.TX_CHUNK, msg_id=42)
        reassembled = b""
        for chunk in chunks:
            _, payload = unpack_message(chunk)
            reassembled += payload
        assert reassembled == data

    def test_too_large_rejected(self):
        data = b"\x00" * (MAX_CHUNK_DATA * 256)
        with pytest.raises(ValueError, match="too large"):
            chunk_payload(data, MsgType.TX_CHUNK)

    def test_msg_id_preserved(self):
        chunks = chunk_payload(b"\xab" * 500, MsgType.TX_CHUNK, msg_id=9999)
        for chunk in chunks:
            header, _ = unpack_message(chunk)
            assert header.msg_id == 9999

    def test_auto_msg_id(self):
        chunks = chunk_payload(b"test", MsgType.TX_CHUNK)
        header, _ = unpack_message(chunks[0])
        assert 0 <= header.msg_id <= 65535


class TestReassemblyBuffer:
    def test_single_chunk(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=1)
        completed = buf.add_chunk(0, b"hello")
        assert completed is True
        assert buf.reassemble() == b"hello"

    def test_multi_chunk(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=3)
        assert not buf.add_chunk(0, b"aaa")
        assert not buf.add_chunk(2, b"ccc")
        assert buf.add_chunk(1, b"bbb")
        assert buf.reassemble() == b"aaabbbccc"

    def test_missing_chunks(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=4)
        buf.add_chunk(0, b"a")
        buf.add_chunk(2, b"c")
        missing = buf.missing_chunks()
        assert 1 in missing
        assert 3 in missing
        assert 0 not in missing

    def test_reassemble_incomplete_raises(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=2)
        buf.add_chunk(0, b"a")
        with pytest.raises(ValueError, match="missing"):
            buf.reassemble()

    def test_expiration(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=1)
        buf.created_at = time.time() - 200
        assert buf.is_expired

    def test_not_expired(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=1)
        assert not buf.is_expired

    def test_duplicate_chunk(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=2)
        buf.add_chunk(0, b"first")
        buf.add_chunk(0, b"replaced")
        buf.add_chunk(1, b"second")
        assert buf.reassemble() == b"replacedsecond"


class TestChunkReassembler:
    def test_single_message(self):
        r = ChunkReassembler()
        result = r.receive_chunk("node1", 1, 0, 1, b"hello")
        assert result == b"hello"

    def test_multi_chunk_reassembly(self):
        r = ChunkReassembler()
        assert r.receive_chunk("node1", 1, 0, 3, b"aaa") is None
        assert r.receive_chunk("node1", 1, 1, 3, b"bbb") is None
        result = r.receive_chunk("node1", 1, 2, 3, b"ccc")
        assert result == b"aaabbbccc"

    def test_out_of_order(self):
        r = ChunkReassembler()
        assert r.receive_chunk("node1", 1, 2, 3, b"ccc") is None
        assert r.receive_chunk("node1", 1, 0, 3, b"aaa") is None
        result = r.receive_chunk("node1", 1, 1, 3, b"bbb")
        assert result == b"aaabbbccc"

    def test_sender_isolation(self):
        r = ChunkReassembler()
        assert r.receive_chunk("node1", 1, 0, 2, b"1a") is None
        assert r.receive_chunk("node2", 1, 0, 2, b"2a") is None
        result1 = r.receive_chunk("node1", 1, 1, 2, b"1b")
        assert result1 == b"1a1b"
        result2 = r.receive_chunk("node2", 1, 1, 2, b"2b")
        assert result2 == b"2a2b"

    def test_cleanup_expired(self):
        r = ChunkReassembler()
        r.receive_chunk("node1", 1, 0, 2, b"data")
        key = ("node1", 1)
        r._buffers[key].created_at = time.time() - 200
        expired = r.cleanup_expired()
        assert len(expired) == 1
        assert key not in r._buffers

    def test_get_missing(self):
        r = ChunkReassembler()
        r.receive_chunk("node1", 1, 0, 3, b"a")
        r.receive_chunk("node1", 1, 2, 3, b"c")
        missing = r.get_missing("node1", 1)
        assert missing == [1]

    def test_get_missing_no_buffer(self):
        r = ChunkReassembler()
        assert r.get_missing("node1", 999) == []

    def test_interleaved_messages(self):
        r = ChunkReassembler()
        assert r.receive_chunk("n1", 10, 0, 2, b"aa") is None
        assert r.receive_chunk("n1", 20, 0, 2, b"bb") is None
        r1 = r.receive_chunk("n1", 10, 1, 2, b"cc")
        assert r1 == b"aacc"
        r2 = r.receive_chunk("n1", 20, 1, 2, b"dd")
        assert r2 == b"bbdd"

    def test_total_chunks_mismatch_raises(self):
        r = ChunkReassembler()
        r.receive_chunk("node1", 1, 0, 3, b"aaa")
        with pytest.raises(ValueError, match="total_chunks mismatch"):
            r.receive_chunk("node1", 1, 1, 5, b"bbb")


class TestChunkerBoundsCheck:
    def test_chunk_num_negative_rejected(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=3)
        with pytest.raises(ValueError, match="out of range"):
            buf.add_chunk(-1, b"data")

    def test_chunk_num_too_high_rejected(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=3)
        with pytest.raises(ValueError, match="out of range"):
            buf.add_chunk(3, b"data")

    def test_chunk_num_equal_to_total_rejected(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=2)
        with pytest.raises(ValueError, match="out of range"):
            buf.add_chunk(2, b"data")

    def test_valid_chunk_nums_accepted(self):
        buf = ReassemblyBuffer(msg_id=1, total_chunks=3)
        buf.add_chunk(0, b"a")
        buf.add_chunk(1, b"b")
        buf.add_chunk(2, b"c")
        assert buf.is_complete
