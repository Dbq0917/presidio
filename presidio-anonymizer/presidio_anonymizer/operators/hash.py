"""Hashes the PII text entity."""

import os
from hashlib import sha256, sha512
from typing import Dict

from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators import Operator, OperatorType
from presidio_anonymizer.services.validators import validate_parameter_in_range


class Hash(Operator):
    """Hash given text with sha256/sha512 algorithm."""

    HASH_TYPE = "hash_type"
    SALT = "salt"
    MIN_SALT_LENGTH = 16
    SHA256 = "sha256"
    SHA512 = "sha512"

    def operate(self, text: str = None, params: Dict = None) -> str:
        """
        Hash given value using sha256 or sha512 with salt.

        :param text: The text to hash
        :param params: Dictionary containing:
            - hash_type: The hash algorithm to use (sha256 or sha512)
            - salt: Optional user-provided salt for reproducible hashing.
                    If not provided, a random salt is generated per entity.
                    Must be at least 16 bytes (128 bits) if provided.
        :return: hashed original text with salt
        """
        params = params or {}
        hash_type = self._get_hash_type_or_default(params)
        salt = self._get_salt(params)

        # Concatenate text and salt before hashing
        salted_text = text.encode("utf-8") + salt

        hash_switcher = {
            self.SHA256: lambda s: sha256(s),
            self.SHA512: lambda s: sha512(s),
        }
        return hash_switcher.get(hash_type)(salted_text).hexdigest()

    def validate(self, params: Dict = None) -> None:
        """Validate the hash type is string and in range of allowed hash types."""
        params = params or {}
        validate_parameter_in_range(
            [self.SHA256, self.SHA512],
            self._get_hash_type_or_default(params),
            self.HASH_TYPE,
            str,
        )
        if self.SALT in params:
            self._validate_salt(params[self.SALT])

    def operator_name(self) -> str:
        """Return operator name."""
        return "hash"

    def _get_hash_type_or_default(self, params: Dict = None):
        params = params or {}
        return params.get(self.HASH_TYPE, self.SHA256)

    def _get_salt(self, params: Dict) -> bytes:
        if self.SALT not in params:
            # Random salt per entity prevents brute-force attacks when the caller
            # does not need referential integrity.
            return os.urandom(32)
        return self._validate_salt(params[self.SALT])

    def _validate_salt(self, salt) -> bytes:
        if isinstance(salt, str):
            salt = salt.encode("utf-8")
        if not isinstance(salt, bytes):
            raise InvalidParamError("Salt parameter must be a string or bytes.")
        if len(salt) == 0:
            raise InvalidParamError(
                "Salt parameter cannot be empty. Either omit the salt parameter "
                "to auto-generate a random salt, or provide a salt of at least "
                "16 bytes (128 bits)."
            )
        if len(salt) < self.MIN_SALT_LENGTH:
            raise InvalidParamError(
                f"Salt must be at least 16 bytes (128 bits). "
                f"Provided salt is {len(salt)} bytes."
            )
        return salt

    def operator_type(self) -> OperatorType:
        """Return operator type."""
        return OperatorType.Anonymize
