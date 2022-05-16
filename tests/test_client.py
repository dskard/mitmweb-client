import json
import pytest

from mitmweb_client import MitmWebClient


class TestClient:
    @pytest.fixture(scope="function", autouse=True)
    def setup(self):
        self.base_uri = "https://localhost:5000"

    @pytest.fixture(scope="function")
    def client(self, requests_mock):
        requests_mock.get(
            f"{self.base_uri}/",
            status_code=200,
            json=None,
            headers={
                "Content-Type": "text/html",
                # setting cookies with Set-Cookie fails in requests-mock:
                # https://github.com/jamielennox/requests-mock/issues/17
                #'Set-Cookie': '_xsrf=blah'
            },
        )

        client = MitmWebClient(self.base_uri)

        # update the xsrf token header to get around requests_mock
        # not being able to set the Set-Cookie header
        client._client.cookies.update({"_xsrf": "mocked_xsrf_token"})

        return client

    def test_initialization(self, requests_mock):
        expected_req_url = f"{self.base_uri}/"
        expected_cookies = {"_xsrf": "blah"}
        requests_mock.get(
            expected_req_url,
            status_code=200,
            headers={
                "Content-Type": "text/html",
                # setting cookies with Set-Cookie fails in requests-mock:
                # https://github.com/jamielennox/requests-mock/issues/17
                #'Set-Cookie': '_xsrf=blah'
            },
        )

        client = MitmWebClient(self.base_uri)

        assert client._uri == self.base_uri
        assert client._client is not None
        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url

    def test_get_filter_help(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/filter-help"
        expected_data = {
            "commands": [
                ["~a", "Match asset in response: CSS, JavaScript, images, fonts."],
                ["~all", "Match all flows"],
            ]
        }

        requests_mock.get(
            expected_req_url,
            status_code=200,
            json=expected_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.get_filter_help()

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_response.status_code == 200
        assert actual_data == expected_data

    def test_get_commands(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/commands"
        expected_resp_data = {
            "flow.decode": "some json data",
            "flow.encode": "more json data",
        }

        requests_mock.get(
            expected_req_url,
            status_code=200,
            json=expected_resp_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.get_commands()

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_execute_command(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/commands/view.order.reverse"
        expected_req_data = json.dumps({"arguments": ["true"]})
        expected_res_data = {"value": None}

        requests_mock.post(
            expected_req_url,
            status_code=200,
            json=expected_res_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.execute_command("view.order.reverse", ["true"])

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == expected_req_data
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert client._last_request.headers["Content-Type"] == "application/json"
        assert client._last_response.status_code == 200
        assert actual_data == expected_res_data

    def test_get_events(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/events"
        expected_resp_data = [
            {"id": 140324928465312, "message": "...", "level": "info"},
            {"id": 140324894186416, "message": "...", "level": "info"},
        ]

        requests_mock.get(
            expected_req_url,
            status_code=200,
            json=expected_resp_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.get_events()

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_get_flows(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/flows"
        expected_resp_data = [
            {
                "id": "f19c661d",
                "intercepted": False,
            },
            {
                "id": "f19c661e",
                "intercepted": False,
            },
            {
                "id": "f19c661f",
                "intercepted": False,
            },
        ]

        requests_mock.get(
            expected_req_url,
            status_code=200,
            json=expected_resp_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.get_flows()

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_resume_flows(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/flows/resume"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.resume_flows()

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_kill_flows(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/flows/kill"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.kill_flows()

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_delete_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}"
        expected_resp_data = ""

        requests_mock.delete(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.delete_flow(flow_id)

        assert client._last_request.method == "DELETE"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_update_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_updates = {"marked": ":red_circle:"}
        expected_req_url = f"{self.base_uri}/flows/{flow_id}"
        expected_resp_data = ""

        requests_mock.put(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.update_flow(flow_id, expected_updates)

        assert client._last_request.method == "PUT"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == json.dumps(expected_updates)
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert client._last_request.headers["Content-Type"] == "application/json"
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_resume_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}/resume"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.resume_flow(flow_id)

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_kill_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}/kill"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.kill_flow(flow_id)

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_duplicate_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}/duplicate"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.duplicate_flow(flow_id)

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_replay_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}/replay"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.replay_flow(flow_id)

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_revert_flow(self, client, requests_mock):
        flow_id = "1234"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}/revert"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.revert_flow(flow_id)

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_get_flow_content_data(self, client, requests_mock):
        flow_id = "1234"
        message = "response"
        expected_req_url = f"{self.base_uri}/flows/{flow_id}/{message}/content.data"
        expected_resp_data = "iVBORw0K..."

        requests_mock.get(
            expected_req_url,
            status_code=200,
            text=expected_resp_data,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.get_flow_content_data(flow_id, message)

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert "X-XSRFToken" not in client._last_request.headers
        assert "Content-Type" not in client._last_request.headers
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_get_flow_content_view(self, client, requests_mock):
        flow_id = "1234"
        message = "response"
        content_view = "Auto"
        expected_req_url = (
            f"{self.base_uri}/flows/{flow_id}/{message}/content/{content_view}"
        )
        expected_resp_data = {"lines": "some json data"}

        requests_mock.get(
            expected_req_url,
            status_code=200,
            json=expected_resp_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.get_flow_content_view(flow_id, message, content_view)

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert "X-XSRFToken" not in client._last_request.headers
        assert "Content-Type" not in client._last_request.headers
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_clear_all(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/clear"
        expected_resp_data = ""

        requests_mock.post(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.clear_all()

        assert client._last_request.method == "POST"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert "Content-Type" not in client._last_request.headers.keys()
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_get_options(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/options"
        expected_resp_data = {
            "add_upstream_certs_to_client_chain": "some json data",
            "allow_hosts": "more json data",
        }

        requests_mock.get(
            expected_req_url,
            status_code=200,
            json=expected_resp_data,
            headers={"Content-Type": "application/json"},
        )

        actual_data = client.get_options()

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert "X-XSRFToken" not in client._last_request.headers
        assert "Content-Type" not in client._last_request.headers
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_update_options(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/options"
        expected_req_data = {"block_list": [":~d myurl\\.org:444"]}
        expected_resp_data = ""

        requests_mock.put(
            expected_req_url,
            status_code=200,
            headers={"Content-Type": "text/html"},
        )

        actual_data = client.update_options(expected_req_data)

        assert client._last_request.method == "PUT"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == json.dumps(expected_req_data)
        assert client._last_request.headers[
            "X-XSRFToken"
        ] == client._client.cookies.get("_xsrf")
        assert client._last_request.headers["Content-Type"] == "application/json"
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data

    def test_get_configuration(self, client, requests_mock):
        expected_req_url = f"{self.base_uri}/conf.js"
        expected_resp_data = "some javascript text"

        requests_mock.get(
            expected_req_url,
            status_code=200,
            text=expected_resp_data,
            headers={"Content-Type": "application/javascript"},
        )

        actual_data = client.get_configuration()

        assert client._last_request.method == "GET"
        assert client._last_request.url == expected_req_url
        assert client._last_request.body == None
        assert "X-XSRFToken" not in client._last_request.headers
        assert "Content-Type" not in client._last_request.headers
        assert client._last_response.status_code == 200
        assert actual_data == expected_resp_data
