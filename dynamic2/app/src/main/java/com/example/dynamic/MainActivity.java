package com.example.dynamic;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.widget.EditText;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import dalvik.system.PathClassLoader;


public class MainActivity extends AppCompatActivity {
    private byte[] dexData = null;
    static {
       System.loadLibrary("anti");
    }
    public native int qemuBkpt();
    public static boolean a() {
//        Log.i("path",System.getenv("PATH"));
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }

    public void aa(){
        finish();
        System.exit(0);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        if(a()||b()||c()){
            Log.i("Foundit", "Here");
            aa();
        }

        int detectionResult = qemuBkpt();

        // Log and display result
        if (detectionResult == 0) {
            Log.i("EmulatorCheck", "Real Device Detected");
//            resultText.setText("Real Device");
        } else {
            Log.e("EmulatorCheck", "Emulator Detected");
//            resultText.setText("Emulator Detected");
        }


        final TextView textView = (TextView) findViewById(R.id.editText);
        final String dwnLink = "https://bashupload.com/lv_Zu/classes.dex?download=1";
        EditText textInputEditText = (EditText) findViewById(R.id.getInput);
        textInputEditText.addTextChangedListener(new TextWatcher() { // from class: com.example.dynamic_load.MainActivity.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String result = MainActivity.this.dexloadDynamicClassFromAssets(MainActivity.this, "classes.dex", "com.example.dynamic.greet");
                textView.setText(result);
//                loadDynamicClassFromAssets(MainActivity.this, dwnLink, "com.example.dynamic.greet", result -> {
//                    textView.setText(result);
//                });

            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });

    }


    private String dexloadDynamicClassFromAssets(Context context, String dexFileName, String className) {
        try {
            // Step 1: Copy the .dex file from assets to codeCacheDir
            File dexFile = new File(context.getCodeCacheDir(), dexFileName);
            if (!dexFile.exists()) {
                try (InputStream inputStream = context.getAssets().open(dexFileName);
                     FileOutputStream outputStream = new FileOutputStream(dexFile)) {
                    byte[] buffer = new byte[4096];
                    int length;
                    while ((length = inputStream.read(buffer)) > 0) {
                        outputStream.write(buffer, 0, length);
                    }
                    outputStream.flush();
                }
            }

            // Step 2: Set up DexClassLoader
            File optimizedDir = context.getCodeCacheDir(); // ✅ Safe location for DEX
            DexClassLoader dexClassLoader = new DexClassLoader(
                    dexFile.getAbsolutePath(),
                    optimizedDir.getAbsolutePath(),
                    null,
                    context.getApplicationContext().getClassLoader() // ✅ Correct ClassLoader
            );

            // Step 3: Load the class dynamically
            Class<?> dynamicClass = dexClassLoader.loadClass(className);
            Object instance = dynamicClass.getDeclaredConstructor().newInstance(); // ✅ Ensure constructor exists

            // Step 4: Get input from EditText safely
            EditText textInputEditText = findViewById(R.id.getInput);
            if (textInputEditText == null) {
                return "Error: EditText not found";
            }

            String inputValue = textInputEditText.getText().toString();

            // Step 5: Call the "Greet" method with input
            return (String) dynamicClass
                    .getMethod("Greet", String.class)
                    .invoke(instance, inputValue);

        } catch (Exception e) {
            e.printStackTrace();
            return "Error: " + e.getMessage();
        }
    }



    private String loadDynamicClassFromAssets(Context context, String dexFileName, String className) {
        try {
            // Step 1: Copy the .dex file from assets to internal storage
            File dexFile = new File(context.getFilesDir(), dexFileName);
            if (!dexFile.exists()) {
                try (InputStream inputStream = context.getAssets().open(dexFileName);
                     FileOutputStream outputStream = new FileOutputStream(dexFile)) {
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = inputStream.read(buffer)) > 0) {
                        outputStream.write(buffer, 0, length);
                    }
                }
            }
            Log.d("Path", getApplicationInfo().nativeLibraryDir);

            Log.d("Path", String.valueOf(context.getFilesDir()));
            // Step 2: Load the .dex file using PathClassLoader
            File optimizedDir = context.getDir("dex", Context.MODE_PRIVATE);
            PathClassLoader pathClassLoader = new PathClassLoader(
                    dexFile.getAbsolutePath(),
                    null,
                    getClassLoader()
            );

            // Step 3: Load the target class and invoke its method
            Class<?> dynamicClass = pathClassLoader.loadClass(className);
            Object instance = dynamicClass.getDeclaredConstructor().newInstance();
            EditText textInputEditText = (EditText)findViewById(R.id.getInput);
            String val = textInputEditText.getText().toString();
            return (String) dynamicClass
                    .getMethod("Greet", String.class) // Replace with your method's signature
                    .invoke(instance, val); // Replace with arguments
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: " + e.getMessage();
        }
    }
    private interface onClassLoadedListener{
        void onClassLoaded(String result);
    }
    private void loadDynamicClassFromAssets(Context context, String link, String className, onClassLoadedListener listener) {
        new Thread(() -> {
            String result = loadDynamicClassFromMemory(link, className);
            runOnUiThread(() -> {
                if (result != null) {
                    // Update the TextView with the result
                    listener.onClassLoaded(result);

                } else {
                    // Handle error if class loading fails
                    TextView textView = findViewById(R.id.editText);
                    textView.setText("Failed to load class.");
                }
            });
        }).start();
    }

    private String loadDynamicClassFromMemory(String link, String className) {
        try {
            // Step 1: Download .dex file if not already downloaded into memory
            if (dexData == null) {
                dexData = downloadDexFile(link);
            }

            // Step 2: Load the class dynamically from the cached .dex data
            InMemoryDexClassLoader dexClassLoader = new InMemoryDexClassLoader(
                    ByteBuffer.wrap(dexData), getClassLoader()
            );
            Class<?> dynamicClass = dexClassLoader.loadClass(className);
            Object instance = dynamicClass.getDeclaredConstructor().newInstance();
            String inputText = ((EditText) findViewById(R.id.getInput)).getText().toString();
            return (String) dynamicClass.getMethod("Greet", String.class).invoke(instance, inputText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    private byte[] downloadDexFile(String link) {
        try {// Download the dex file from the given link and store it in memory
            BufferedInputStream inputStream = new BufferedInputStream(new URI(link).toURL().openStream());
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, bytesRead);
            }

            // Return the byte array of the downloaded dex file
            return byteArrayOutputStream.toByteArray();
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}


