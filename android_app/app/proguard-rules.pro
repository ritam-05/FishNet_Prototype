# Keep ONNX Runtime classes used via JNI/reflection.
-keep class ai.onnxruntime.** { *; }
-dontwarn ai.onnxruntime.**

# Keep Kotlin metadata and generic signatures for runtime interop.
-keepattributes Signature, InnerClasses, EnclosingMethod, RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
