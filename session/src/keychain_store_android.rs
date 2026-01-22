use config::session::PREFS_NAME;
use errors::keychain::KeyChainErrors;
use errors::session::SessionErrors;
use jni::objects::{JByteArray, JObject, JString, JValue};
use jni::JNIEnv;
use jni::JavaVM;
use secrecy::{ExposeSecret, SecretSlice};
use std::sync::OnceLock;
use tokio::sync::oneshot;
use zeroize::Zeroize;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

fn map_jni_error(e: jni::errors::Error) -> SessionErrors {
    SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn JNI_OnLoad(
    vm: jni::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    if JAVA_VM.set(vm).is_err() {
        return jni::sys::JNI_VERSION_1_6;
    }

    let vm = JAVA_VM.get().unwrap();
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(_) => return jni::sys::JNI_VERSION_1_6,
    };

    let context = match try_get_context_via_activity_thread(&mut env) {
        Ok(ctx) => ctx,
        Err(_) => return jni::sys::JNI_VERSION_1_6,
    };

    let context_global = match env.new_global_ref(&context) {
        Ok(g) => g,
        Err(_) => return jni::sys::JNI_VERSION_1_6,
    };

    let vm_ptr = vm.get_java_vm_pointer();
    unsafe {
        ndk_context::initialize_android_context(
            vm_ptr.cast(),
            context_global.as_obj().as_raw().cast(),
        );
    }
    std::mem::forget(context_global);

    jni::sys::JNI_VERSION_1_6
}

fn with_android_context<F, T>(op: F) -> Result<T, SessionErrors>
where
    F: FnOnce(&mut JNIEnv, &JObject) -> Result<T, SessionErrors>,
{
    let vm = JAVA_VM.get().ok_or_else(|| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(
            "JavaVM not initialized".into(),
        ))
    })?;

    let mut env = vm.attach_current_thread().map_err(map_jni_error)?;
    let ctx_ptr = ndk_context::android_context().context();

    if ctx_ptr.is_null() {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("Context is null".into()),
        ));
    }

    let context = unsafe { JObject::from_raw(ctx_ptr.cast()) };
    op(&mut env, &context)
}

fn try_get_context_via_activity_thread<'local>(
    env: &mut JNIEnv<'local>,
) -> Result<JObject<'local>, SessionErrors> {
    let activity_thread_class = env
        .find_class("android/app/ActivityThread")
        .map_err(map_jni_error)?;

    let current_application = env
        .call_static_method(
            activity_thread_class,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    if current_application.is_null() {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("currentApplication returned null".into()),
        ));
    }

    Ok(current_application)
}

fn get_prefs<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject,
) -> Result<JObject<'local>, SessionErrors> {
    let name = env.new_string(PREFS_NAME).map_err(map_jni_error)?;
    env.call_method(
        context,
        "getSharedPreferences",
        "(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        &[JValue::Object(name.as_ref()), JValue::Int(0)],
    )
    .map_err(map_jni_error)?
    .l()
    .map_err(map_jni_error)
}

fn persist_data(
    env: &mut JNIEnv,
    context: &JObject,
    key: &str,
    value: &str,
) -> Result<(), SessionErrors> {
    let prefs = get_prefs(env, context)?;
    let editor = env
        .call_method(
            &prefs,
            "edit",
            "()Landroid/content/SharedPreferences$Editor;",
            &[],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    let k = env.new_string(key).map_err(map_jni_error)?;
    let v = env.new_string(value).map_err(map_jni_error)?;

    env.call_method(
        &editor,
        "putString",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        &[JValue::Object(k.as_ref()), JValue::Object(v.as_ref())],
    )
    .map_err(map_jni_error)?;

    env.call_method(&editor, "apply", "()V", &[])
        .map_err(map_jni_error)?;

    Ok(())
}

fn fetch_data(env: &mut JNIEnv, context: &JObject, key: &str) -> Result<String, SessionErrors> {
    let prefs = get_prefs(env, context)?;
    let k = env.new_string(key).map_err(map_jni_error)?;
    let def = env.new_string("").map_err(map_jni_error)?;

    let val = env
        .call_method(
            &prefs,
            "getString",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            &[JValue::Object(k.as_ref()), JValue::Object(def.as_ref())],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    let result: String = env
        .get_string(&JString::from(val))
        .map_err(map_jni_error)?
        .into();

    Ok(result)
}

fn delete_data(env: &mut JNIEnv, context: &JObject, key: &str) -> Result<(), SessionErrors> {
    let prefs = get_prefs(env, context)?;
    let editor = env
        .call_method(
            &prefs,
            "edit",
            "()Landroid/content/SharedPreferences$Editor;",
            &[],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    let k = env.new_string(key).map_err(map_jni_error)?;

    env.call_method(
        &editor,
        "remove",
        "(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        &[JValue::Object(k.as_ref())],
    )
    .map_err(map_jni_error)?;

    env.call_method(&editor, "apply", "()V", &[])
        .map_err(map_jni_error)?;

    Ok(())
}

fn find_class_from_context<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject,
    class_name: &str,
) -> Result<jni::objects::JClass<'local>, SessionErrors> {
    let class_loader = env
        .call_method(context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    let class_name_jstring = env.new_string(class_name).map_err(map_jni_error)?;

    let class = env
        .call_method(
            &class_loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&class_name_jstring)],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    Ok(jni::objects::JClass::from(class))
}

fn get_biometric_manager<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject,
) -> Result<JObject<'local>, SessionErrors> {
    let biometric_class = find_class_from_context(env, context, "biometric.BiometricManager")?;

    env.new_object(
        biometric_class,
        "(Landroid/content/Context;)V",
        &[JValue::Object(context)],
    )
    .map_err(map_jni_error)
}

fn get_activity<'local>(env: &mut JNIEnv<'local>) -> Result<JObject<'local>, SessionErrors> {
    let activity_thread_class = env
        .find_class("android/app/ActivityThread")
        .map_err(map_jni_error)?;

    let current_activity_thread = env
        .call_static_method(
            activity_thread_class,
            "currentActivityThread",
            "()Landroid/app/ActivityThread;",
            &[],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    if current_activity_thread.is_null() {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("currentActivityThread returned null".into()),
        ));
    }

    let activities = env
        .get_field(
            &current_activity_thread,
            "mActivities",
            "Landroid/util/ArrayMap;",
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    if activities.is_null() {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("mActivities is null".into()),
        ));
    }

    let size = env
        .call_method(&activities, "size", "()I", &[])
        .map_err(map_jni_error)?
        .i()
        .map_err(map_jni_error)?;

    if size == 0 {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("No activities found".into()),
        ));
    }

    let activity_record = env
        .call_method(
            &activities,
            "valueAt",
            "(I)Ljava/lang/Object;",
            &[JValue::Int(0)],
        )
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    let activity = env
        .get_field(&activity_record, "activity", "Landroid/app/Activity;")
        .map_err(map_jni_error)?
        .l()
        .map_err(map_jni_error)?;

    if activity.is_null() {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("Activity is null".into()),
        ));
    }

    Ok(activity)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_biometric_RustBiometricCallback_nativeOnSuccess(
    env: JNIEnv,
    _class: JObject,
    callback_ptr: jni::sys::jlong,
    data: JByteArray,
) {
    let data_vec = match env.convert_byte_array(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    let sender =
        unsafe { Box::from_raw(callback_ptr as *mut oneshot::Sender<Result<SecretSlice<u8>, String>>) };
    let _ = sender.send(Ok(SecretSlice::new(data_vec.into())));
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_biometric_RustBiometricCallback_nativeOnError(
    mut env: JNIEnv,
    _class: JObject,
    callback_ptr: jni::sys::jlong,
    message: jni::objects::JString,
) {
    let error_msg = match env.get_string(&message) {
        Ok(s) => s.into(),
        Err(_) => "Unknown error".to_string(),
    };

    let sender =
        unsafe { Box::from_raw(callback_ptr as *mut oneshot::Sender<Result<SecretSlice<u8>, String>>) };
    let _ = sender.send(Err(error_msg));
}

async fn call_biometric_operation<F>(op: F) -> Result<SecretSlice<u8>, SessionErrors>
where
    F: FnOnce(
        &mut JNIEnv,
        &JObject,
        &JObject,
        &JObject,
        jni::sys::jlong,
    ) -> Result<(), SessionErrors>,
{
    let (tx, rx) = oneshot::channel::<Result<SecretSlice<u8>, String>>();
    let callback_ptr = Box::into_raw(Box::new(tx)) as jni::sys::jlong;

    with_android_context(|env, context| {
        let biometric_manager = get_biometric_manager(env, context)?;
        let activity = get_activity(env)?;
        let callback_class =
            find_class_from_context(env, context, "biometric.RustBiometricCallback")?;
        let callback = env
            .new_object(callback_class, "(J)V", &[JValue::Long(callback_ptr)])
            .map_err(map_jni_error)?;

        op(env, &biometric_manager, &activity, &callback, callback_ptr)
    })?;

    rx.await
        .map_err(|_| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(
                "Callback channel closed".into(),
            ))
        })?
        .map_err(|e| SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e)))
}

pub async fn store_key_in_secure_enclave(
    mut key: SecretSlice<u8>,
    wallet_key: &str,
) -> Result<(), SessionErrors> {
    let mut key_vec = key.expose_secret().to_vec();
    let wallet_key_owned = wallet_key.to_string();

    let encrypted_data = call_biometric_operation(move |env, manager, activity, callback, _ptr| {
        let key_array = env.byte_array_from_slice(&key_vec).map_err(map_jni_error)?;

        let result = env.call_method(
            manager,
            "encryptKeyAsync",
            "(Landroidx/fragment/app/FragmentActivity;[BLbiometric/BiometricCallback;)V",
            &[
                JValue::Object(activity),
                JValue::Object(&key_array.into()),
                JValue::Object(callback),
            ],
        )
        .map_err(map_jni_error);

        key_vec.zeroize();
        result
    })
    .await?;

    let result = with_android_context(|env, context| {
        persist_data(
            env,
            context,
            &wallet_key_owned,
            &hex::encode(encrypted_data.expose_secret()),
        )
    });

    key.zeroize();

    result
}

pub async fn retrieve_key_from_secure_enclave(
    wallet_key: &str,
) -> Result<SecretSlice<u8>, SessionErrors> {
    let encrypted_hex = with_android_context(|env, context| fetch_data(env, context, wallet_key))?;

    if encrypted_hex.is_empty() {
        return Err(SessionErrors::KeychainError(
            KeyChainErrors::AppleKeychainError("No data found".into()),
        ));
    }

    let mut encrypted_data = hex::decode(encrypted_hex).map_err(|_| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(
            "Failed to decode encrypted data".into(),
        ))
    })?;

    call_biometric_operation(move |env, manager, activity, callback, _ptr| {
        let data_array = env
            .byte_array_from_slice(&encrypted_data)
            .map_err(map_jni_error)?;

        let result = env.call_method(
            manager,
            "decryptKeyAsync",
            "(Landroidx/fragment/app/FragmentActivity;[BLbiometric/BiometricCallback;)V",
            &[
                JValue::Object(activity),
                JValue::Object(&data_array.into()),
                JValue::Object(callback),
            ],
        )
        .map_err(map_jni_error);

        encrypted_data.zeroize();
        result
    })
    .await
}

pub async fn delete_key_from_secure_enclave(wallet_key: &str) -> Result<(), SessionErrors> {
    with_android_context(|env, context| {
        delete_data(env, context, wallet_key)?;

        let biometric_manager = get_biometric_manager(env, context)?;

        let result = env
            .call_method(&biometric_manager, "deleteKey", "()Z", &[])
            .map_err(map_jni_error)?
            .z()
            .map_err(map_jni_error)?;

        if !result {
            return Err(SessionErrors::KeychainError(
                KeyChainErrors::AppleKeychainError("Failed to delete biometric key".into()),
            ));
        }

        Ok(())
    })
}

pub fn device_biometric_type() -> Result<String, SessionErrors> {
    with_android_context(|env, context| {
        let biometric_manager = get_biometric_manager(env, context)?;

        let biometric_type = env
            .call_method(
                &biometric_manager,
                "biometricType",
                "()Ljava/lang/String;",
                &[],
            )
            .map_err(map_jni_error)?
            .l()
            .map_err(map_jni_error)?;

        let jstring = jni::objects::JString::from(biometric_type);
        let type_str = env.get_string(&jstring).map_err(map_jni_error)?;

        Ok(type_str.into())
    })
}
