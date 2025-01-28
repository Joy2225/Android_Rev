package com.example.dynamic;

import android.content.Context;
import android.os.Bundle;
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

import dalvik.system.InMemoryDexClassLoader;
import dalvik.system.PathClassLoader;

public class MainActivity extends AppCompatActivity {
    private interface onClassLoadedListener{
        void onClassLoaded(String result);
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

    private void loadDynamicClassFromAssets(Context context, String link, String className, onCLassLoadedListener listener) {
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