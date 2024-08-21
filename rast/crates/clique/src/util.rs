
use std::fmt;







#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Error indicating an expected value was not found.
pub struct Mismatch<T> {
	/// Value expected.
	pub expected: T,
	/// Value found.
	pub found: T,
}

impl<T: fmt::Display> fmt::Display for Mismatch<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_fmt(format_args!("Expected {}, found {}", self.expected, self.found))
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Error indicating value found is outside of a valid range.
pub struct OutOfBounds<T> {
	/// Minimum allowed value.
	pub min: Option<T>,
	/// Maximum allowed value.
	pub max: Option<T>,
	/// Value found.
	pub found: T,
}

impl<T> OutOfBounds<T> {
	pub fn map<F, U>(self, map: F) -> OutOfBounds<U>
		where F: Fn(T) -> U
	{
		OutOfBounds {
			min: self.min.map(&map),
			max: self.max.map(&map),
			found: map(self.found),
		}
	}
}

impl<T: fmt::Display> fmt::Display for OutOfBounds<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match (self.min.as_ref(), self.max.as_ref()) {
			(Some(min), Some(max)) => format!("Min={}, Max={}", min, max),
			(Some(min), _) => format!("Min={}", min),
			(_, Some(max)) => format!("Max={}", max),
			(None, None) => "".into(),
		};

		f.write_fmt(format_args!("Value {} out of bounds. {}", self.found, msg))
	}
}
