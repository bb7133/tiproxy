// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    Cursor, DecodeError, EncodeError, LengthEncodedInt, encode_length_encoded_bytes,
    encode_length_encoded_int, length_encoded_int_size,
};

/// One borrowed connection-attribute key/value pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    /// Raw attribute key bytes.
    pub key: &'a [u8],
    /// Raw attribute value bytes.
    pub value: &'a [u8],
}

/// A validated, allocation-free view of a connection-attribute body.
///
/// The body excludes the outer length-encoded size. Keys and values yielded by
/// [`ConnectionAttributes::iter`] borrow directly from the original packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionAttributes<'a> {
    encoded: &'a [u8],
    count: usize,
}

impl<'a> ConnectionAttributes<'a> {
    /// Validates an attribute body without allocating a map or copying strings.
    ///
    /// Duplicate keys and byte ordering are preserved. Policy layers may choose
    /// map semantics later without losing wire evidence here.
    ///
    /// # Errors
    ///
    /// Returns a typed error for truncated, overflowing, NULL, or non-canonical
    /// key/value encodings.
    pub fn parse(encoded: &'a [u8]) -> Result<Self, DecodeError> {
        let mut cursor = Cursor::new(encoded);
        let mut count = 0_usize;
        while !cursor.is_empty() {
            read_required_bytes(&mut cursor, "connection attribute key")?;
            read_required_bytes(&mut cursor, "connection attribute value")?;
            count = count.checked_add(1).ok_or(DecodeError::LengthOverflow {
                field: "connection attribute count",
                offset: cursor.position(),
                value: u64::MAX,
            })?;
        }
        Ok(Self { encoded, count })
    }

    /// Returns an empty attribute view.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            encoded: &[],
            count: 0,
        }
    }

    /// Returns the raw encoded attribute body.
    #[must_use]
    pub const fn encoded(self) -> &'a [u8] {
        self.encoded
    }

    /// Returns the number of validated key/value pairs.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }

    /// Returns whether there are no attributes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Iterates over borrowed key/value pairs in their original wire order.
    #[must_use]
    pub fn iter(self) -> AttributeIter<'a> {
        AttributeIter {
            cursor: Cursor::new(self.encoded),
        }
    }
}

impl<'a> IntoIterator for ConnectionAttributes<'a> {
    type Item = Result<Attribute<'a>, DecodeError>;
    type IntoIter = AttributeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over a validated connection-attribute body.
#[derive(Debug, Clone)]
pub struct AttributeIter<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = Result<Attribute<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_empty() {
            return None;
        }
        let key = match read_required_bytes(&mut self.cursor, "connection attribute key") {
            Ok(key) => key,
            Err(error) => return Some(Err(error)),
        };
        let value = match read_required_bytes(&mut self.cursor, "connection attribute value") {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        Some(Ok(Attribute { key, value }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

fn read_required_bytes<'a>(
    cursor: &mut Cursor<'a>,
    field: &'static str,
) -> Result<&'a [u8], DecodeError> {
    let offset = cursor.position();
    match cursor.read_length_encoded_bytes(field)? {
        Some(value) => Ok(value),
        None => Err(DecodeError::UnexpectedNull { field, offset }),
    }
}

/// Appends an outer-length-prefixed connection-attribute sequence.
///
/// The function computes the body size first and writes directly into `output`;
/// it does not create a temporary attribute map or body buffer.
///
/// # Errors
///
/// Returns a typed overflow error if any host length or aggregate body length
/// cannot be represented by the protocol.
pub fn encode_connection_attributes(
    attributes: &[Attribute<'_>],
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let body_length = attributes.iter().try_fold(0_usize, |length, attribute| {
        let key_length =
            u64::try_from(attribute.key.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "connection attribute key",
                length: attribute.key.len(),
            })?;
        let value_length =
            u64::try_from(attribute.value.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "connection attribute value",
                length: attribute.value.len(),
            })?;
        length
            .checked_add(length_encoded_int_size(key_length))
            .and_then(|length| length.checked_add(attribute.key.len()))
            .and_then(|length| length.checked_add(length_encoded_int_size(value_length)))
            .and_then(|length| length.checked_add(attribute.value.len()))
            .ok_or(EncodeError::LengthOverflow {
                field: "connection attributes",
                length: usize::MAX,
            })
    })?;
    let body_length_u64 = u64::try_from(body_length).map_err(|_| EncodeError::LengthOverflow {
        field: "connection attributes",
        length: body_length,
    })?;
    encode_length_encoded_int(body_length_u64, output);
    for attribute in attributes {
        encode_length_encoded_bytes(Some(attribute.key), output)?;
        encode_length_encoded_bytes(Some(attribute.value), output)?;
    }
    Ok(())
}

/// Borrows and validates an outer-length-prefixed connection-attribute body.
pub(crate) fn read_prefixed_attributes<'a>(
    cursor: &mut Cursor<'a>,
) -> Result<Option<ConnectionAttributes<'a>>, DecodeError> {
    let length_offset = cursor.position();
    let length = match cursor.read_length_encoded_int()? {
        LengthEncodedInt::Null => return Ok(None),
        LengthEncodedInt::Value(value) => {
            usize::try_from(value).map_err(|_| DecodeError::LengthOverflow {
                field: "connection attributes",
                offset: length_offset,
                value,
            })?
        }
    };
    let remaining = cursor.remaining();
    if length > remaining {
        return Err(DecodeError::LengthExceedsInput {
            field: "connection attributes",
            offset: cursor.position(),
            declared: length,
            remaining,
        });
    }
    ConnectionAttributes::parse(cursor.take(length, "connection attributes")?).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_round_trip_preserves_order_duplicates_and_borrowing()
    -> Result<(), Box<dyn std::error::Error>> {
        let attributes = [
            Attribute {
                key: b"program_name",
                value: b"mysql",
            },
            Attribute {
                key: b"program_name",
                value: b"mysqlsh",
            },
            Attribute {
                key: b"empty",
                value: b"",
            },
        ];
        let mut encoded = Vec::new();
        encode_connection_attributes(&attributes, &mut encoded)?;
        let mut cursor = Cursor::new(&encoded);
        let parsed = read_prefixed_attributes(&mut cursor)?.ok_or(DecodeError::UnexpectedNull {
            field: "connection attributes",
            offset: 0,
        })?;
        assert_eq!(parsed.len(), attributes.len());
        assert_eq!(
            parsed.encoded(),
            &encoded[cursor.position() - parsed.encoded().len()..]
        );
        let decoded: Result<Vec<_>, _> = parsed.iter().collect();
        assert_eq!(decoded, Ok(attributes.to_vec()));
        assert!(cursor.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_null_and_truncated_attribute_fields() {
        assert!(matches!(
            ConnectionAttributes::parse(&[0xfb, 0]),
            Err(DecodeError::UnexpectedNull { .. })
        ));
        assert!(matches!(
            ConnectionAttributes::parse(&[2, b'a']),
            Err(DecodeError::LengthExceedsInput { .. })
        ));
        assert!(matches!(
            ConnectionAttributes::parse(&[1, b'k']),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }
}
