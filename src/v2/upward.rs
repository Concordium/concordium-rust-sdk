/// Type for forward-compatibility with the Concordium Node API.
///
/// Wraps enum types which are expected to be extended some future version of
/// the Concordium Node API allowing the current SDK version to handle when new
/// variants are introduced in the API, unknown to this version of the SDK.
/// This is also used for helper methods extracting deeply nested information.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Upward<A> {
    /// New unknown variant, the structure is not known to the current version
    /// of this library. Consider updating the library if support is needed.
    Unknown,
    /// Known variant.
    Known(A),
}

impl<A> Upward<A> {
    /// Returns the contained [`Upward::Known`] value, consuming the `self`
    /// value.
    ///
    /// # Panics
    ///
    /// Panics if the self value equals [`Upward::Unknown`].
    pub fn unwrap(self) -> A {
        match self {
            Self::Known(value) => value,
            Self::Unknown => panic!("called `Upward::unwrap()` on an `Unknown` value"),
        }
    }

    /// Transforms `Upward<T>` into a [`Option<T>`] where [`Option::Some`]
    /// represents [`Upward::Known`] and [`Option::None`] represents
    /// [`Upward::Unknown`].
    pub fn known(self) -> Option<A> { Option::from(self) }

    /// Borrow `Upward<T>` aa [`Option<&T>`] where [`Option::Some`]
    /// represents [`Upward::Known`] and [`Option::None`] represents
    /// [`Upward::Unknown`].
    pub fn as_known(&self) -> Option<&A> { Option::from(self.as_ref()) }

    /// Transforms the `Upward<T>` into a [`Result<T, E>`], mapping
    /// [`Known(v)`] to [`Ok(v)`] and [`Upward::Unknown`] to [`Err(err)`].
    ///
    /// Arguments passed to `ok_or` are eagerly evaluated; if you are passing
    /// the result of a function call, it is recommended to use
    /// [`ok_or_else`], which is lazily evaluated.
    ///
    /// [`Ok(v)`]: Ok
    /// [`Err(err)`]: Err
    /// [`Known(v)`]: Upward::Known
    /// [`ok_or_else`]: Upward::ok_or_else
    pub fn ok_or<E>(self, error: E) -> Result<A, E> { Option::from(self).ok_or(error) }

    /// Transforms the `Upward<T>` into a [`Result<T, E>`], mapping
    /// [`Known(v)`] to [`Ok(v)`] and [`Upward::Unknown`] to [`Err(err())`].
    ///
    /// [`Ok(v)`]: Ok
    /// [`Err(err())`]: Err
    /// [`Known(v)`]: Upward::Known
    pub fn ok_or_else<E, F>(self, error: F) -> Result<A, E>
    where
        F: FnOnce() -> E, {
        Option::from(self).ok_or_else(error)
    }

    /// Returns `true` if the Upward is a [`Upward::Known`] and the value inside
    /// of it matches a predicate.
    pub fn is_known_and(self, f: impl FnOnce(A) -> bool) -> bool {
        Option::from(self).is_some_and(f)
    }

    /// Maps an `Upward<A>` to `Upward<U>` by applying a function to a contained
    /// value (if `Known`) or returns `Unknown` (if `Unknown`).
    pub fn map<U, F>(self, f: F) -> Upward<U>
    where
        F: FnOnce(A) -> U, {
        match self {
            Self::Known(x) => Upward::Known(f(x)),
            Self::Unknown => Upward::Unknown,
        }
    }

    /// Converts from `&Option<A>` to `Option<&A>`.
    pub const fn as_ref(&self) -> Upward<&A> {
        match *self {
            Self::Known(ref x) => Upward::Known(x),
            Self::Unknown => Upward::Unknown,
        }
    }

    /// Require the data to be known, converting it from `Upward<A>` to
    /// `Result<A, RequireDataError>`.
    ///
    /// This is effectively opt out of forward-compatibility, forcing the
    /// library to be up to date with the node version.
    pub fn require(self) -> Result<A, RequireDataError> { self.ok_or(RequireDataError) }
}

impl<A> From<Option<A>> for Upward<A> {
    fn from(value: Option<A>) -> Self {
        if let Some(n) = value {
            Self::Known(n)
        } else {
            Self::Unknown
        }
    }
}

impl<A> From<Upward<A>> for Option<A> {
    fn from(value: Upward<A>) -> Self {
        if let Upward::Known(n) = value {
            Some(n)
        } else {
            None
        }
    }
}

impl<A> serde::Serialize for Upward<A>
where
    A: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        if let Upward::Known(a) = self {
            a.serialize(serializer)
        } else {
            Err(serde::ser::Error::custom(
                "Cannot serialize Upward::Unknown due",
            ))
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Encountered some unknown data structure was marked as required to be known")]
pub struct RequireDataError;
