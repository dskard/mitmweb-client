import textwrap
import requests
import json


class MitmWebClientException(Exception):
    def __init__(self, response):
        self.response = response

    def __repr__(self):
        return f"<{self.__class__.__name__} status={self.response.status_code}>"

    def __str__(self):
        req = self.response.request
        return textwrap.dedent(
            f"""
            Failed to execute {self.__class__.__name__} request:
            \t{req.method} {req.url}
            Body:
            \t{req.body}
            Response status code:
            \t{self.response.status_code}
            Response body:
            \t{self.response.text}
            """
        ).strip()


class MitmWebClient:
    def __init__(self, uri, headers={}, proxies={}):
        self._uri = uri
        self._client = requests.Session()

        # save the last request and response so we can
        # confirm they were formatted correctly in the unit tests
        self._last_request = None
        self._last_response = None

        self._client.headers.update(
            {"User-Agent": "mitmweb_client (+https://github.com/dskard/mitmweb-client)"}
        )
        self._client.headers.update(headers)

        self._client.proxies.update(proxies)

        result = self._http("GET", "/")

    def _check_status(self, response):
        if response.status_code >= 400:
            raise MitmWebClientException(response)

    def _http(self, method, uri, **kwargs):

        # add the X-XSRFToken header if we are changing the state of the server
        if method in ["DELETE", "PATCH", "POST", "PUT"]:
            if "headers" not in kwargs:
                kwargs["headers"] = {}

            kwargs["headers"].update(
                {
                    "X-XSRFToken": self._client.cookies.get("_xsrf"),
                }
            )

        endpoint = self._uri + uri

        req = requests.Request(method, endpoint, **kwargs)
        prepped = self._client.prepare_request(req)
        settings = self._client.merge_environment_settings(
            prepped.url, {}, None, None, None
        )
        resp = self._client.send(prepped, **settings)

        self._last_request = prepped
        self._last_response = resp

        self._check_status(resp)

        return resp

    def get_filter_help(self):
        """retrieve filter documentation from the server

        usage:
            get_filter_help()

        returns application/json:
            {
                "commands": [
                    ["~a", "Match asset in response: CSS, JavaScript, images, fonts."],
                    ["~all", "Match all flows"],
                    ...
                ]
            }
        """

        response = self._http("GET", "/filter-help")
        return response.json()

    def get_commands(self):
        """retrieve commands from the server

        usage:
            get_commands()

        returns application/json:
            {
                "value": null
            }
        """

        response = self._http("GET", "/commands")
        return response.json()

    def execute_command(self, command, arguments=[]):
        """execute a mitmproxy command

        usage:
            execute_command("view.order.reverse", ["true"])

        returns application/json:
            {
                value: null
            }
        """

        headers = {"Content-Type": "application/json"}
        args = {"arguments": arguments}
        response = self._http(
            "POST", f"/commands/{command}", data=json.dumps(args), headers=headers
        )
        return response.json()

    def get_events(self):
        """retrieve events data from the server

        usage:
            get_events()

        returns application/json:
            [
                {"id": 140324928465312, "message": "...", "level": "info"},
                {"id": 140324894186416, "message": "...", "level": "info"},
            ]
        """

        response = self._http("GET", "/events")
        return response.json()

    def get_flows(self):
        """retrieve flows data from the server

        usage:
            get_flows()

        returns application/json:
            [
                {"id": "f19c661d", "intercepted": false, ...},
                {"id": "f19c661e", "intercepted": false, ...},
                {"id": "f19c661f", "intercepted": false, ...},
            ]
        """

        response = self._http("GET", "/flows")
        return response.json()

    # def dump_flows(self):
    #    # save
    #    # this returns a file, need to figure out how to return that to caller
    #    return self._http("GET", "/flows/dump")

    # def ???_flows_dump(self):
    #    return self._http("POST", "/flows/dump")

    def resume_flows(self):
        """resume all intercepted flows

        usage:
            resume_flows()

        returns text/html:
            ""
        """

        response = self._http("POST", "/flows/resume")
        return response.text

    def kill_flows(self):
        """kill all intercepted flows

        usage:
            kill_flows()

        returns text/html:
            ""
        """

        response = self._http("POST", "/flows/kill")
        return response.text

    def delete_flow(self, flow_id):
        """delete an individual flow

        usage:
            delete_flow()

        returns text/html:
            ""
        """

        response = self._http("DELETE", f"/flows/{flow_id}")
        return response.text

    def update_flow(self, flow_id, updates={}):
        """update an individual flow

        updates is a dictionary.

        for a request it looks something like:
        {
           "requests": {
               "host": "www.url.com",
               "path": "/favicon.png",
               "port": 443,
               "scheme": "https",
               "content": "",
               "method": "POST",
               "http_version": "HTTP/2.0",
               "headers":[["user-agent","Mozilla/5.0"], ...],
               "trailers": ???
           }
        }

        for a response:
        {
           "response": {
               "msg": "",
               "code": 200,
               "content": "",
               "http_version": "HTTP/2.0",
               "headers":[["user-agent","Mozilla/5.0"], ...],
               "trailers": ???
           }
        }

        for a mark:
        {
           "marked": ":red_circle:"
        }

        usage:
            update_flow("e9a1daaf", {"marked": ":red_circle:"})

        returns text/html:
            ""
        """

        headers = {"Content-Type": "application/json"}
        response = self._http(
            "PUT", f"/flows/{flow_id}", data=json.dumps(updates), headers=headers
        )
        return response.text

    def resume_flow(self, flow_id):
        """update an individual flow

        usage:
            resume_flow("e9a1daaf")

        returns text/html:
            ""
        """

        response = self._http("POST", f"/flows/{flow_id}/resume")
        return response.text

    def kill_flow(self, flow_id):
        """kill an individual flow

        usage:
            kill_flow("e9a1daaf")

        returns text/html:
            ""
        """

        response = self._http("POST", f"/flows/{flow_id}/kill")
        return response.text

    def duplicate_flow(self, flow_id):
        """duplicate an individual flow

        usage:
            duplicate_flow("e9a1daaf")

        returns text/html:
            ""
        """

        response = self._http("POST", f"/flows/{flow_id}/duplicate")
        return response.text

    def replay_flow(self, flow_id):
        """replay an individual flow

        usage:
            replay_flow("e9a1daaf")

        returns text/html:
            ""
        """

        response = self._http("POST", f"/flows/{flow_id}/replay")
        return response.text

    def revert_flow(self, flow_id):
        """revert an individual flow

        usage:
            revert_flow("e9a1daaf")

        returns text/html:
            ""
        """

        response = self._http("POST", f"/flows/{flow_id}/revert")
        return response.text

    def get_flow_content_data(self, flow_id, message):
        """retrieve the flow's content data

        message is one of request, response, messages

        usage:
            get_flow_content_data("e9a1daaf", "response")

        returns text/html (maybe base64 encoded string for images):
            "iVBORw0K..."
        """

        response = self._http("GET", f"/flows/{flow_id}/{message}/content.data")
        return response.text

    # def set_flow_content_data(self, flow_id, message):
    #    """upload a file with new content data for a flow
    #
    #    message is one of request, response, messages
    #
    #    need to send Content-Type, Content-Disposition headers. probably something like:
    #    Content-Type for the request may need to be a `multipart/form-data;boundary=....`
    #    ```
    #    filename = re.sub(r'[^-\w" .()]', "", filename)
    #    cd = f"attachment; filename={filename}"
    #    self.set_header("Content-Disposition", cd)
    #    self.set_header("Content-Type", "application/text")
    #    self.set_header("X-Content-Type-Options", "nosniff")
    #    self.set_header("X-Frame-Options", "DENY")
    #    ```
    #
    #    Payload looks something like:
    #    ```
    #    -----------------------------24530444051929662106965338188
    #    Content-Disposition: form-data; name="file"; filename="blob"i
    #    Content-Type: plain/text
    #    ...PNG
    #    ...
    #    ```
    #    """
    #
    #    return self._http("POST", f"/flows/{flow_id}/{message}/content.data")

    def get_flow_content_view(self, flow_id, message, content_view):
        """retrieve the flow's content view

        message is one of request, response, messages
        content_view is usually "Auto.json
        mitmweb ui also sends `?lines=81` as request arguments, maybe we should also add these.

        usage:
            get_flow_content_view("e9a1daaf", "response", )

        returns application/json:
            {
                "lines": [
                    [["header", "Format:                "], ["text", "Portable network graphics"]],
                    [["header", "Size:                  "], ["text", "16 x 16 px"]],
                    [["header", "gamma:                 "], ["text", "0.45455"]],
                    [["header", "aspect:                "], ["text", "281 x 281"]],
                    [["header", "date:create:           "], ["text", "2019-06-27T06:18:22+02:00"]],
                    [["header", "date:modify:           "], ["text", "2019-06-27T06:18:22+02:00"]],
                    [["header", "Software:              "], ["text", "www.inkscape.org"]],
                    [["header", "Raw profile type iptc: "], ["text", "\nIPTC profile\n      28\n30\n"]]],
                    "description": "PNG Image"
                }
            }
        """

        response = self._http(
            "GET", f"/flows/{flow_id}/{message}/content/{content_view}"
        )
        return response.json()

    def clear_all(self):
        """clear all flows and events data

        usage:
            clear_all()

        returns text/html:
            ""
        """

        response = self._http("POST", "/clear")
        return response.text

    def get_options(self):
        """retrieve options from the server

        usage:
            get_options()

        returns application/json:
            {
                "add_upstream_certs_to_client_chain": {
                    "type": "bool",
                    "default": false,
                    "value": false,
                    "help": "Add all certificates...",
                    "choices": null
                },
                "allow_hosts": {
                    "type": "sequence of str",
                    "default": [],
                    "value": [],
                    "help": "Opposite of --ignore-hosts.",
                    "choices": null
                },
                ...
            }
        """

        response = self._http("GET", "/options")
        return response.json()

    def update_options(self, options):
        """update options on the server

        options is a dictionary like:
            {
                "block_list": [ ":~d myurl\\.org:444" ]
            }

        usage:
            update_options( {"block_list":[":~d myurl\\.org:444"]} )

        returns text/html:
            ""
        """

        headers = {"Content-Type": "application/json"}
        response = self._http(
            "PUT", "/options", data=json.dumps(options), headers=headers
        )
        return response.text

    # def save_options(self):
    #    """not implemented on the server
    #    """
    #    return self._http("POST", "/options/save")

    def get_configuration(self):
        """retrieve the server configuration

        usage:
            get_configuration()

        returns application/javascript:
            ""
        """

        response = self._http("GET", "/conf.js")
        return response.text
