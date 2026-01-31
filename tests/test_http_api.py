"""Tests for the BaseMesh HTTP API layer."""

import pytest
from unittest.mock import MagicMock, patch

from basemesh.constants import WEI_PER_ETH, PROTOCOL_VERSION
from basemesh.config import GatewayConfig
from basemesh.gateway import GatewayNode
from basemesh.wallet import WalletManager

from mock_mesh import MockMeshInterface

# Skip entire module if fastapi/httpx not installed
fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from basemesh.http_api import create_api


API_KEY = "test-api-key-12345"


@pytest.fixture
def http_setup(tmp_wallet_dir):
    """Set up a GatewayNode with HTTP API enabled, using mocked Web3."""
    mesh = MockMeshInterface()
    wm = WalletManager(wallet_dir=tmp_wallet_dir)
    wm.create_wallet("hotwallt", passphrase="gwpass")

    config = GatewayConfig(
        hot_wallet="hotwallt",
        allowed_requesters=[],
        max_transfer_eth=1.0,
        max_transfer_token_units=0,
        max_requests_per_minute=100.0,
        rate_limit_burst=10,
        http_port=8420,
        api_key=API_KEY,
    )

    with patch("basemesh.gateway.Web3") as MockWeb3:
        mock_w3 = MagicMock()
        mock_w3.eth.gas_price = 1_000_000_000
        mock_w3.eth.get_transaction_count.return_value = 5
        mock_w3.eth.get_balance.return_value = 10 * WEI_PER_ETH
        mock_w3.eth.send_raw_transaction.return_value = b"\xab" * 32
        mock_w3.eth.chain_id = 84532
        MockWeb3.return_value = mock_w3
        MockWeb3.HTTPProvider = MagicMock()

        gw = GatewayNode(
            mesh=mesh,
            rpc_url="http://localhost:8545",
            chain_id=84532,
            wallet_manager=wm,
            gateway_config=config,
        )
        gw._hot_private_key = wm.load_private_key("hotwallt", passphrase="gwpass")
        gw._hot_address = wm.get_address("hotwallt")
        gw._w3 = mock_w3

        app = create_api(gw)
        client = TestClient(app)

        yield client, gw, mock_w3


def _headers(key=API_KEY):
    return {"X-API-Key": key}


class TestAuth:
    def test_missing_api_key_returns_422(self, http_setup):
        client, _, _ = http_setup
        resp = client.get("/v1/status")
        assert resp.status_code == 422

    def test_wrong_api_key_returns_401(self, http_setup):
        client, _, _ = http_setup
        resp = client.get("/v1/status", headers=_headers("wrong-key"))
        assert resp.status_code == 401

    def test_correct_api_key_returns_200(self, http_setup):
        client, _, _ = http_setup
        resp = client.get("/v1/status", headers=_headers())
        assert resp.status_code == 200


class TestStatusEndpoint:
    def test_response_fields(self, http_setup):
        client, gw, _ = http_setup
        resp = client.get("/v1/status", headers=_headers())
        data = resp.json()
        assert data["status"] == "ok"
        assert data["chain_id"] == 84532
        assert data["protocol_version"] == PROTOCOL_VERSION
        assert data["hot_wallet_address"] == gw._hot_address
        assert "hot_wallet" in data["capabilities"]
        assert "balance" in data["capabilities"]

    def test_no_hot_wallet(self, http_setup):
        client, gw, _ = http_setup
        gw._hot_address = None
        resp = client.get("/v1/status", headers=_headers())
        data = resp.json()
        assert data["hot_wallet_address"] is None
        assert "hot_wallet" not in data["capabilities"]


class TestBalanceEndpoint:
    def test_eth_balance(self, http_setup):
        client, _, mock_w3 = http_setup
        resp = client.get(
            "/v1/balance/0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            headers=_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["balance_wei"] == 10 * WEI_PER_ETH
        assert data["token_address"] is None

    def test_erc20_balance(self, http_setup):
        client, _, mock_w3 = http_setup
        mock_contract = MagicMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 5_000_000
        mock_w3.eth.contract.return_value = mock_contract

        resp = client.get(
            "/v1/balance/0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            params={"token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
            headers=_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["balance_wei"] == 5_000_000
        assert data["token_address"] is not None

    def test_rpc_error_returns_502(self, http_setup):
        client, _, mock_w3 = http_setup
        mock_w3.eth.get_balance.side_effect = Exception("connection refused")
        resp = client.get(
            "/v1/balance/0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            headers=_headers(),
        )
        assert resp.status_code == 502


class TestGasEndpoint:
    def test_gas_price(self, http_setup):
        client, _, _ = http_setup
        resp = client.get("/v1/gas", headers=_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["gas_price_wei"] == 1_000_000_000
        assert data["chain_id"] == 84532


class TestNonceEndpoint:
    def test_nonce_query(self, http_setup):
        client, _, _ = http_setup
        resp = client.get(
            "/v1/nonce/0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            headers=_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["nonce"] == 5


class TestTransferEndpoint:
    def test_eth_transfer_success(self, http_setup):
        client, gw, mock_w3 = http_setup
        # _broadcast_to_base returns (True, tx_hash)
        with patch.object(gw, "_broadcast_to_base", return_value=(True, "0xdeadbeef")):
            resp = client.post(
                "/v1/transfer",
                json={
                    "to": gw._hot_address,
                    "amount_wei": WEI_PER_ETH // 10,
                },
                headers=_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["tx_hash"] == "0xdeadbeef"

    def test_no_hot_wallet_returns_503(self, http_setup):
        client, gw, _ = http_setup
        gw._hot_private_key = None
        resp = client.post(
            "/v1/transfer",
            json={"to": "0x" + "22" * 20, "amount_wei": 1000},
            headers=_headers(),
        )
        assert resp.status_code == 503

    def test_exceeds_eth_limit(self, http_setup):
        client, _, _ = http_setup
        resp = client.post(
            "/v1/transfer",
            json={
                "to": "0x" + "22" * 20,
                "amount_wei": 2 * WEI_PER_ETH,  # max is 1 ETH
            },
            headers=_headers(),
        )
        assert resp.status_code == 400
        assert "limit" in resp.json()["detail"].lower()

    def test_broadcast_failure(self, http_setup):
        client, gw, _ = http_setup
        with patch.object(gw, "_broadcast_to_base",
                          return_value=(False, "nonce too low")):
            resp = client.post(
                "/v1/transfer",
                json={
                    "to": gw._hot_address,
                    "amount_wei": WEI_PER_ETH // 100,
                },
                headers=_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "nonce" in data["error"].lower()


class TestRateLimit:
    def test_rate_limited_returns_429(self, http_setup):
        client, gw, _ = http_setup
        # Exhaust the rate limiter for the HTTP key prefix
        key_id = f"http:{API_KEY[:8]}"
        while gw._rate_limiter.is_allowed(key_id):
            pass  # Drain tokens

        resp = client.get("/v1/status", headers=_headers())
        assert resp.status_code == 429


class TestOpenApiSpec:
    def test_openapi_json_available(self, http_setup):
        client, _, _ = http_setup
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["info"]["title"] == "BaseMesh Gateway API"
        assert "/v1/status" in spec["paths"]
        assert "/v1/transfer" in spec["paths"]
        assert "/v1/balance/{address}" in spec["paths"]
        assert "/v1/gas" in spec["paths"]
        assert "/v1/nonce/{address}" in spec["paths"]
