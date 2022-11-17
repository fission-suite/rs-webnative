use std::{fmt::Debug, rc::Rc};

use crate::{fs::JsResult, value};
use js_sys::{Array, Error, Object, Reflect};
use wasm_bindgen::JsValue;
use wnfs::{
    private::{PrivateDirectory as WnfsPrivateDirectory, PrivateForest as WnfsPrivateForest},
    public::PublicDirectory as WnfsPublicDirectory,
    Metadata,
};

use super::{metadata::JsMetadata, PrivateDirectory, PrivateFile, PrivateForest, PublicDirectory};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn error<E>(message: &str) -> impl FnOnce(E) -> js_sys::Error + '_
where
    E: Debug,
{
    move |e| Error::new(&format!("{message}: {e:?}"))
}

pub(crate) fn map_to_rust_vec<T, F: FnMut(JsValue) -> JsResult<T>>(
    array: &Array,
    f: F,
) -> JsResult<Vec<T>> {
    array
        .to_vec()
        .into_iter()
        .map(f)
        .collect::<JsResult<Vec<_>>>()
}

pub(crate) fn convert_path_segments(path_segments: &Array) -> JsResult<Vec<String>> {
    map_to_rust_vec(path_segments, |v| {
        v.as_string()
            .ok_or_else(|| Error::new("Invalid path segments: Expected an array of strings"))
    })
}

pub(crate) fn create_public_op_result<T: Into<JsValue>>(
    root_dir: Rc<WnfsPublicDirectory>,
    result: T,
) -> JsResult<JsValue> {
    let op_result = Object::new();

    Reflect::set(
        &op_result,
        &value!("rootDir"),
        &PublicDirectory(root_dir).into(),
    )
    .map_err(error("Failed to set rootDir"))?;
    Reflect::set(&op_result, &value!("result"), &result.into())
        .map_err(error("Failed to set result"))?;

    Ok(value!(op_result))
}

pub(crate) fn create_private_op_result<T: Into<JsValue>>(
    root_dir: Rc<WnfsPrivateDirectory>,
    hamt: Rc<WnfsPrivateForest>,
    result: T,
) -> JsResult<JsValue> {
    let op_result = Array::new();

    Reflect::set(
        &op_result,
        &value!("rootDir"),
        &PrivateDirectory(root_dir).into(),
    )
    .map_err(error("Failed to set rootDir"))?;
    Reflect::set(&op_result, &value!("hamt"), &PrivateForest(hamt).into())
        .map_err(error("Failed to set hamt"))?;
    Reflect::set(&op_result, &value!("result"), &result.into())
        .map_err(error("Failed to set result"))?;

    Ok(value!(op_result))
}

pub(crate) fn create_private_file_result(
    file: PrivateFile,
    hamt: PrivateForest,
) -> JsResult<JsValue> {
    let op_result = Array::new();

    Reflect::set(&op_result, &value!(0), &file.into()).map_err(error("Failed to set file"))?;
    Reflect::set(&op_result, &value!(1), &hamt.into()).map_err(error("Failed to set hamt"))?;

    Ok(value!(op_result))
}

pub(crate) fn create_ls_entry(name: &String, metadata: &Metadata) -> JsResult<JsValue> {
    let entry = Object::new();

    Reflect::set(&entry, &value!("name"), &value!(name)).map_err(error("Failed to set name"))?;
    Reflect::set(
        &entry,
        &value!("metadata"),
        &JsMetadata(metadata).try_into()?,
    )
    .map_err(error("Failed to set metadata"))?;

    Ok(value!(entry))
}
