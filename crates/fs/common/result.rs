use std::rc::Rc;

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// The result of an operation applied to a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpResult<T, U> {
    /// The root directory.
    pub root_dir: Rc<T>,
    /// Implementation dependent but it usually the last leaf node operated on.
    pub result: U,
}
