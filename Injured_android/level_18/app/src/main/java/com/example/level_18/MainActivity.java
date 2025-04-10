package com.example.level_18;

import static androidx.core.content.FileProvider.getUriForFile;

import static java.security.AccessController.getContext;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {

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

        File imagePath = new File(this.getFilesDir(), "/");
        File newFile = new File(imagePath, "test");
//        Log.d("aa", newFile.toString());
        Uri contentUri = getUriForFile(this, "b3nac.injuredandroid.fileprovider", newFile);
//        Log.d("aaa", contentUri.toString());
        Intent intent = new Intent();
        intent.setData(contentUri);
        intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        intent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagEighteenActivity");
        ActivityResultLauncher<Intent> mStartForResult = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if (result.getResultCode() == Activity.RESULT_OK) {
                            Intent intent = result.getData();
                            // Handle the Intent
                            Uri uri = intent.getData();
                            try {
                                InputStream in = getContentResolver().openInputStream(uri);
                                BufferedReader r = new BufferedReader(new InputStreamReader(in));
                                StringBuilder total = new StringBuilder();
                                for (String line; (line = r.readLine()) != null; ) {
                                    total.append(line).append('\n');
                                }

                                String content = total.toString();
                                Log.d("Content", content);


                            }catch (Exception e) {
                            }
                        }
                    }
                });

        mStartForResult.launch(intent);
    }
}