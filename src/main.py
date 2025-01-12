# BSD 3-Clause License
#
# Copyright (c) 2020-2024, Faster Speeding
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""Github webhook bot which runs alongside github Actions to elevate actions."""
import contextlib
import dataclasses
import datetime
import enum
import hmac
import uuid
import io
import logging
import os
import re
import pathlib
import subprocess
import sys
import tempfile
import time
import traceback
import types
import typing
import zipfile
from collections import abc as collections
from typing import Self

import anyio
import anyio.lowlevel
import anyio.to_thread
import dotenv
import fastapi
import httpx
import jwt
from . import config
import starlette.middleware
from anyio.streams import memory as streams
from asgiref import typing as asgiref
from dateutil import parser as dateutil

_LOGGER = logging.getLogger("piped.bot")
_LOGGER.setLevel("INFO")

dotenv.load_dotenv()

_username = os.environ.get("CLIENT_NAME", default="always-on-duty") + "[bot]"

with httpx.Client() as client:
    _user_id = int(client.get(f"https://api.github.com/users/{_username}").json()["id"])

APP_ID = os.environ["APP_ID"]
COMMIT_ENV = {
    "GIT_AUTHOR_NAME": _username,
    "GIT_AUTHOR_EMAIL": f"{_user_id}+{_username}@users.noreply.github.com",
    "GIT_COMMITTER_NAME": _username,
}
COMMIT_ENV["GIT_COMMITTER_EMAIL"] = COMMIT_ENV["GIT_AUTHOR_EMAIL"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"].encode()
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()
jwt_instance = jwt.JWT()

_TAG_MATCH = re.compile(r"v.+\..+\..+")


@dataclasses.dataclass(kw_only=True, slots=True)
class _ScopeIndex:
    """Index of the PRs being processed."""

    _closed: bool = False
    _scopes: dict[uuid.UUID, anyio.CancelScope] = dataclasses.field(default_factory=dict)

    def is_closed(self) -> bool:
        return self._closed

    @contextlib.contextmanager
    def scope(self) -> collections.Generator[typing.Any, anyio.CancelScope]:
        if self._closed:
            raise RuntimeError("Closed")

        scope = anyio.CancelScope()
        scope_id = uuid.uuid4()
        self._scopes[scope_id] = scope

        try:
            with scope:
                yield scope

        finally:
            self._scopes.pop(scope_id, None)

    async def close(self) -> None:
        """Cancel all active processing tasks."""
        if self._closed:
            raise RuntimeError("Already closed")

        _LOGGER.info("Stopping all current calls")

        end_time = time.time() + (60 * 5)

        while self._scopes and time.time() > end_time:
            await anyio.sleep(0.5)

        for scope in self._scopes.values():
            scope.cancel()

        await anyio.lowlevel.checkpoint()  # Yield to the loop to let these cancels propagate


class _Tokens:
    """Index of the Github API tokens this application has authorised."""

    __slots__ = ("_installation_tokens", "_private_key")

    def __init__(self) -> None:
        private_key = os.environ["PRIVATE_KEY"].strip()
        if private_key.startswith("-"):
            private_key = private_key.encode()

        else:
            private_key = pathlib.Path(private_key).read_bytes()

        self._installation_tokens: dict[int, tuple[datetime.datetime, str]] = {}
        self._private_key = jwt.jwk_from_pem(private_key)

    def app_token(self, *, on_gen: collections.Callable[[str], None] | None = None) -> str:
        """Generate an application app token.

        !!! warning
            This cannot does not provide authorization for repos or
            organisations the application is authorised in.

        Parameters
        ----------
        on_gen
            Called on new token generation.

            This is for log filtering.
        """
        now = int(time.time())
        token = jwt_instance.encode(
            {"iat": now - 60, "exp": now + 60 * 2, "iss": APP_ID}, self._private_key, alg="RS256"
        )

        if on_gen:
            on_gen(token)

        return token

    async def installation_token(
        self,
        http: httpx.AsyncClient,
        installation_id: int,
        /,
        *,
        on_gen: collections.Callable[[str], None] | None = None,
    ) -> str:
        """Authorise an installation specific token.

        This is used to authorise organisation and repo actions and will return
        cached tokens.

        Parameters
        ----------
        http
            REST client to use to authorise the token.
        installation_id
            ID of the installation to authorise a token for.
        on_gen
            Called on new token generation for both app and installation tokens.

            This is for log filtering.

        Returns
        -------
        str
            The generated installation token.
        """
        if token_info := self._installation_tokens.get(installation_id):
            expire_by = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(seconds=60)
            if token_info[0] >= (expire_by):
                return token_info[1]

        # TODO: do we need/want to use an async lock here?
        response = await _request(
            http,
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            json={"permissions": {"actions": "read", "checks": "write", "contents": "write", "workflows": "write"}},
            token=self.app_token(on_gen=on_gen),
        )
        data = response.json()
        token: str = data["token"]
        if on_gen:
            on_gen(token)

        self._installation_tokens[installation_id] = (dateutil.isoparse(data["expires_at"]), token)
        return token


async def _request(
    http: httpx.AsyncClient,
    method: typing.Literal["GET", "PATCH", "POST", "DELETE"],
    endpoint: str,
    /,
    *,
    json: dict[str, typing.Any] | None = None,
    query: dict[str, str] | None = None,
    output: typing.IO[str] | None = None,
    token: str | None = None,
) -> httpx.Response:
    """Make a request to Github's API.

    Parameters
    ----------
    http
        The REST client to use to make the request.
    method
        HTTP method to use for this request.
    endpoint
        Endpoint to request to.

        This will be appended to `"https://api.github.com"` if it doesn't
        start with `"https://"`.
    json
        Dict of the JSON payload to include in this request.
    query
        Dict of the query string parameters to include for this request.
    output
        IO object to print error output to on failed requests.
    token
        The authorisation token to use.
    """
    if not endpoint.startswith("https://"):
        endpoint = f"https://api.github.com{endpoint}"

    headers = {"X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if json:
        headers["Content-Type"] = "application/vnd.github+json"

    response = await http.request(method, endpoint, follow_redirects=True, headers=headers, json=json, params=query)

    try:
        response.raise_for_status()
    except Exception:
        print("Response body:", file=output or sys.stderr)
        print(response.read().decode(), file=output or sys.stderr)
        raise

    return response


class _CachedReceive:
    """Helper ASGI event receiver which first returned the cached request body."""

    __slots__ = ("_data", "_receive")

    def __init__(self, data: bytearray, receive: asgiref.ASGIReceiveCallable) -> None:
        self._data: bytearray | None = data  # TODO: should this be chunked?
        self._receive = receive  # TODO: check this behaviour

    async def __call__(self) -> asgiref.ASGIReceiveEvent:
        if not self._data:
            return await self._receive()

        # Bytearray does work here, just this isn't typed as allowing it.
        data = typing.cast("bytes", self._data)
        self._data = None
        return {"type": "http.request", "body": data, "more_body": False}


async def _error_response(send: asgiref.ASGISendCallable, body: bytes = b"", /, *, status_code: int = 403) -> None:
    """Return a quick RESTful error response.

    Parameters
    ----------
    send
        The ASGI send callback to use to send this response.
    body
        The error message.
    status_code
        The error's status code.
    """
    headers: list[tuple[bytes, bytes]] = []

    if body:
        headers.append((b"content-type", b"text/plain; charset=UTF-8"))

    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
            "trailers": False,
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _find_headers(scope: asgiref.HTTPScope, headers: collections.Collection[bytes]) -> dict[bytes, bytes]:
    """Extract specific headers from an ASGI request.

    Parameters
    ----------
    scope
        The ASGI HTTP scope payload to get the headers from.
    headers
        Collection of the headers to find.

    Returns
    -------
    dict[bytes, bytes]
        Dictionary of the found headers.
    """
    results: dict[bytes, bytes] = {}

    for header_name, header_value in scope["headers"]:
        name = header_name.lower()
        if name in headers:
            results[name] = header_value

            if len(results) == len(headers):
                break

    return results


# TODO: check user agent header starts with "GitHub-Hookshot/"?
class AuthMiddleware:
    """ASGI signature authorisation middleware."""

    __slots__ = ("app",)

    # starlette.types.ASGIApp is more appropriate but less concise than this callable type.
    def __init__(
        self,
        app: collections.Callable[
            [asgiref.Scope, asgiref.ASGIReceiveCallable, asgiref.ASGISendCallable], collections.Awaitable[None]
        ],
    ) -> None:
        """Initialise an Auth Middleware.

        Parameters
        ----------
        app
            The ASGI App this middleware wraps.
        """
        self.app = app

    async def __call__(
        self, scope: asgiref.Scope, receive: asgiref.ASGIReceiveCallable, send: asgiref.ASGISendCallable
    ) -> None:
        """Execute a REST request received as an ASGI event.

        Parameters
        ----------
        scope
            Scope of the ASGI event.
        receive
            ASGI callback used to receive the request's body/data.
        send
            ASGI callback used to respond to the request.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        signature = _find_headers(scope, (b"x-hub-signature-256",)).get(b"x-hub-signature-256")
        if not signature:
            await _error_response(send, b"")
            return

        more_body = True
        payload = bytearray()
        while more_body:
            event = await receive()
            match event:
                case {"type": "http.request"}:
                    more_body = event.get("more_body", False)
                    payload.extend(event.get("body") or b"")
                case _:
                    raise NotImplementedError

        digest = "sha256=" + hmac.new(WEBHOOK_SECRET, payload, digestmod="sha256").hexdigest()

        if not hmac.compare_digest(signature.decode(), digest):
            await _error_response(send, b"Invalid signature", status_code=401)
            return

        await self.app(scope, _CachedReceive(payload, receive), send)


@dataclasses.dataclass(slots=True)
class _Workflow:
    name: str
    workflow_id: int


class _WorkflowAction(str, enum.Enum):
    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"
    REQUESTED = "requested"



class _IterWorkflows:
    """Async iterable of received workflow finishes."""

    __slots__ = ("_filter", "_recv")

    def __init__(self, recv: streams.MemoryObjectReceiveStream[tuple[int, str, _WorkflowAction]], /) -> None:
        self._filter: collections.Collection[str] = ()
        self._recv = recv

    async def __aiter__(self) -> collections.AsyncIterator[_Workflow]:
        timeout_at = time.time() + 5
        waiting_on = dict.fromkeys(self._filter, False)

        while waiting_on:
            if not any(waiting_on.values()):
                if time.time() > timeout_at:
                    break

                timeout = timeout_at

            else:
                timeout = None

            try:
                with anyio.fail_after(timeout):
                    workflow_id, name, action = await self._recv.receive()

            except TimeoutError:
                return

            if name not in waiting_on:
                continue

            if action is _WorkflowAction.COMPLETED:
                del waiting_on[name]
                yield _Workflow(name, workflow_id)

            else:
                waiting_on[name] = True

    def filter_names(self, names: collections.Collection[str], /) -> Self:
        """Set this to only track specific workflows.

        This will override any previously set filter.

        Parameters
        ----------
        names
            Collection of workflow names to filter for.

        Returns
        -------
        typing.Self
            The async workflow iterable.
        """
        self._filter = names
        return self


async def _on_startup() -> None:
    app.state.http = httpx.AsyncClient()
    app.state.index = _ProcessingIndex()
    app.state.tokens = _Tokens()
    app.state.workflows = _WorkflowDispatch()


async def _on_shutdown() -> None:
    assert isinstance(app.state.index, _ProcessingIndex)
    assert isinstance(app.state.http, httpx.AsyncClient)
    await app.state.index.close()
    await app.state.http.aclose()


auth = starlette.middleware.Middleware(AuthMiddleware)  # pyright: ignore[reportArgumentType]
app = fastapi.FastAPI(middleware=[auth])
app.router.on_startup.append(_on_startup)
app.router.on_shutdown.append(_on_shutdown)


@app.post("/webhook")
async def post_webhook(
    body: dict[str, typing.Any],
    request: fastapi.Request,
    tasks: fastapi.BackgroundTasks,
    x_github_event: typing.Annotated[str, fastapi.Header()],
) -> fastapi.Response:
    """Receive Github action triggered event webhooks."""
    assert isinstance(request.app.state.http, httpx.AsyncClient)
    assert isinstance(request.app.state.index, _ScopeIndex)
    assert isinstance(request.app.state.tokens, _Tokens)
    assert isinstance(request.app.state.workflows, _WorkflowDispatch)
    http = request.app.state.http
    index = request.app.state.index
    tokens = request.app.state.tokens
    workflows = request.app.state.workflows
    match (x_github_event, body):
        case ("create", {"ref": ref, "ref_type": "tag", "repository": repo_data}):
            print("neet", ref, repo_data)
            if _TAG_MATCH.fullmatch(ref.removeprefix("refs/tags/")):
                ...

        case ("push", {"after": after, "deleted": False, "master_branch": master_branch, "ref": ref, "repository": repo_data}):
            print("beat", after, master_branch, ref, repo_data)
            if ref == f"refs/heads/{master_branch}":
                print("beat me")


        # case ("pull_request", {"action": "closed", "number": number, "repository": repo_data}):
        #     index.stop_for_pr(int(repo_data["id"]), int(number), repo_name=repo_data["full_name"])
        #     await anyio.lowlevel.checkpoint()  # Yield to the loop to let these cancels propagate

        # case ("pull_request", {"action": "opened" | "reopened" | "synchronize"}):
        #     tasks.add_task(_process_repo, http, tokens, index, workflows, body)
        #     return fastapi.Response(status_code=202)

        # case ("workflow_run", _):
        #     workflows.consume_event(body)

        # case ("installation", {"action": "removed", "repositories_removed": repositories_removed}):
        #     for repo in repositories_removed:
        #         index.clear_for_repo(int(repo["id"]))

        #     await anyio.lowlevel.checkpoint()  # Yield to the loop to let these cancels propagate

        # case ("installation_repositories", {"action": "removed", "repositories": repositories}):
        #     for repo in repositories:
        #         index.clear_for_repo(int(repo["id"]))

        #     await anyio.lowlevel.checkpoint()  # Yield to the loop to let these cancels propagate

        case _:
            _LOGGER.info(
                "Ignoring unexpected event type %r. These events should be disabled for this app", x_github_event
            )
            return fastapi.Response("Event type not implemented", status_code=501)

    return fastapi.Response(status_code=204)


@contextlib.asynccontextmanager
async def _with_cloned(
    output: typing.IO[str], url: str, /, *, branch: str = "master"
) -> collections.AsyncGenerator[pathlib.Path, None]:
    """Async context manager which shallow clones a repo into a temporary directory.

    Parameters
    ----------
    output
        String file-like object this should pipe GIT's output to.
    url
        URL of the repository to clone.

        This must include an installation which is authorised for
        `contents: write`.
        (`https://x-access-token:<token>@github.com/owner/repo.git`)
    branch
        The branch to clone.
    """
    temp_dir = await anyio.to_thread.run_sync(lambda: tempfile.TemporaryDirectory[str](ignore_cleanup_errors=True))
    try:
        await run_process(output, ["git", "clone", url, "--depth", "1", "--branch", branch, temp_dir.name])
        yield pathlib.Path(temp_dir.name)

    finally:
        # TODO: this just fails on Windows sometimes
        with anyio.CancelScope(shield=True):
            await anyio.to_thread.run_sync(temp_dir.cleanup)


class _RunCheck:
    """Context manager which manages the Github check suite for this application."""

    __slots__ = ("_check_id", "_commit_hash", "_filter_from_logs", "_http", "_output", "_repo_name", "_token")

    def __init__(self, http: httpx.AsyncClient, /, *, token: str, repo_name: str, commit_hash: str) -> None:
        """Initialise this context manager.

        Parameters
        ----------
        http
            REST client to use to manage the check suite.
        token
            Installation token to use to authorise the check suite requests.

            This must be authorised for `checks: write`.
        repo_name
            The repo's full name in the format `"{owner_name}/{repo_name}"`.
        commit_hash
            Hash of the commit this run is for.
        """
        self._check_id = -1
        self._commit_hash = commit_hash
        self._filter_from_logs = [token]
        self._http = http
        self._output = io.StringIO()
        self._repo_name = repo_name
        self._token = token

    @property
    def output(self) -> io.StringIO:
        return self._output

    async def __aenter__(self) -> Self:
        result = await _request(
            self._http,
            "POST",
            f"/repos/{self._repo_name}/check-runs",
            json={"name": "Inspecting PR", "head_sha": self._commit_hash},
            output=self._output,
            token=self._token,
        )
        self._check_id = int(result.json()["id"])
        return self

    async def __aexit__(
        self,
        exc_cls: type[BaseException] | None,
        exc: BaseException | None,
        traceback_value: types.TracebackType | None,
    ) -> None:
        self._output.seek(0)
        output = {}

        if exc:
            conclusion = "failure" if isinstance(exc, Exception) else "cancelled"
            output["title"] = "Error"
            output["summary"] = _censor(str(exc), self._filter_from_logs)
            self._output.write("\n")
            self._output.write("```python\n")
            traceback.print_exception(exc_cls, exc, traceback_value, file=self._output)
            self._output.write("```\n")

        else:
            conclusion = "success"
            output["title"] = output["summary"] = "Success"

        # TODO: charlimit
        text = "\n".join(_censor(line, self._filter_from_logs) for line in self._output)
        output["text"] = f"```\n{text}\n```"

        # TODO: https://docs.github.com/en/get-started/writing-on-github/
        # working-with-advanced-formatting/creating-and-highlighting-code-blocks
        with anyio.CancelScope(shield=True):
            await _request(
                self._http,
                "PATCH",
                f"/repos/{self._repo_name}/check-runs/{self._check_id}",
                json={"conclusion": conclusion, "output": output},
                output=self._output,
                token=self._token,
            )

    def filter_from_logs(self, value: str, /) -> Self:
        """Mark a string as being filtered out of the logs.

        Parameters
        ----------
        value
            String to censor from logs.
        """
        self._filter_from_logs.append(value)
        return self

    async def mark_running(self) -> None:
        """Mark the check suite as running.

        Raises
        ------
        RuntimeError
            If called outside of this context manager's context.
        """
        if self._check_id == -1:
            error_message = "Not running yet"
            raise RuntimeError(error_message)

        await _request(
            self._http,
            "PATCH",
            f"/repos/{self._repo_name}/check-runs/{self._check_id}",
            json={"started_at": datetime.datetime.now(tz=datetime.UTC).isoformat(), "status": "in_progress"},
            output=self._output,
            token=self._token,
        )


def _censor(value: str, filters: list[str], /) -> str:
    for filter_ in filters:
        value.replace(filter_, "***")

    return value


async def _process_repo(
    http: httpx.AsyncClient,
    tokens: _Tokens,
    index: _ScopeIndex,
    workflows: _WorkflowDispatch,

) -> None:

    with (
        index.scope(),
        workflows.track_workflows(repo_id, head_repo_id, head_sha) as tracked_workflows,
    ):
        token = await tokens.installation_token(http, installation_id)
        git_url = f"https://x-access-token:{token}@github.com/{head_name}.git"
        run_ctx = _RunCheck(http, token=token, repo_name=full_name, commit_hash=head_sha)
        _LOGGER.info("Cloning %s:%s branch %s", full_name, pr_id, head_ref)

        async with run_ctxm _with_cloned(run_ctx.output, git_url, branch=head_ref) as temp_dir_path:
            config_ = await config.Config.read_async(temp_dir_path)
            if not config_.bot_actions:
                _LOGGER.warning("Received event from %s repo with no bot_wait_for", full_name)
                return

            await run_ctx.mark_running()
            async for workflow in tracked_workflows.filter_names(config_.bot_actions):
                await _apply_patch(http, run_ctx.output, token, full_name, workflow, cwd=temp_dir_path)

            await run_process(run_ctx.output, ["git", "push"], cwd=temp_dir_path)



async def run_process(
    output: typing.IO[str],
    command: str | bytes | collections.Sequence[str | bytes],
    *,
    input: bytes | None = None,  # noqa: A002
    check: bool = True,
    cwd: str | bytes | os.PathLike[str] | None = None,
    env: collections.Mapping[str, str] | None = None,
) -> None:
    """Run a CLI command asynchronously and capture its output.

    Parameters
    ----------
    output
        IO object to pipe the command call's output to.
    command
        The command to execute.
    input
        Bytes passed to the standard input of the subprocess.
    check
        If [True][], raise [anyio.CalledProcessError][] if
        the process terminates with a return code other than
        0.
    cwd
        Working directory to run this command in.
    env
        Mapping of environment variables to set for the
        command call.
    """
    try:
        # TODO: could --3way or --unidiff-zero help with conflicts here?
        result = await anyio.run_process(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=input, check=check, cwd=cwd, env=env
        )

    except subprocess.CalledProcessError as exc:
        assert isinstance(exc.stdout, bytes)
        output.write(exc.stdout.decode())
        raise

    else:
        output.write(result.stdout.decode())
