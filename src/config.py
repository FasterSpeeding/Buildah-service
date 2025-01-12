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
"""Utility library used by Piped."""

from __future__ import annotations

__all__ = []

import dataclasses
import pathlib
import tomllib
import typing
from typing import Self

if typing.TYPE_CHECKING:
    from collections import abc as collections


_DEFAULT_ACTIONS = ["Freeze PR dependency changes", "Resync piped", "Reformat PR code", "Run Rustfmt"]


@dataclasses.dataclass(kw_only=True, slots=True)
class Config:
    """Configuration class for the project config."""

    bot_actions: set[str]

    @classmethod
    def read(cls, base_path: pathlib.Path, /) -> Self:
        for file_name, extractor in _TOML_PARSER.items():
            path = base_path / file_name
            if not path.exists():
                continue

            with path.open("rb") as file:
                data = extractor(tomllib.load(file))
                break

        else:
            error_message = "Couldn't find config file"
            raise RuntimeError(error_message)

        bot_actions = set(_validate_list_entry(data, "bot_actions", str, default_factory=_DEFAULT_ACTIONS.copy))
        return cls(
            bot_actions=bot_actions,
        )

    @classmethod
    async def read_async(cls, base_path: pathlib.Path, /) -> Self:
        import anyio.to_thread

        return await anyio.to_thread.run_sync(cls.read, base_path)


_TOML_PARSER: dict[str, collections.Callable[[dict[str, typing.Any]], dict[str, typing.Any]]] = {
    "pyproject.toml": lambda data: data["tool"]["piped"],
    "piped.toml": lambda data: data,
}
