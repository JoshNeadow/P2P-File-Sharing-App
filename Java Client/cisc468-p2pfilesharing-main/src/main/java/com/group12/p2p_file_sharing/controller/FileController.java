package com.group12.p2p_file_sharing.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.group12.p2p_file_sharing.model.FileDesc;

@RestController
@RequestMapping("/api/files")
public class FileController {

    @Value("${file_directory:available-files}")
    private String FILE_DIR;

    @GetMapping("/list")
    public List<FileDesc> listFiles() {
        File uploadDir = new File(FILE_DIR);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }

        String[] fileNames = uploadDir.list();
        List<FileDesc> fileDescList = new ArrayList<>();

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            for (String fileName : fileNames) {
                File file = new File(FILE_DIR, fileName);
                String hash = calculateSHA256(file, digest);
                fileDescList.add(new FileDesc(fileName, hash));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return fileDescList;
    }

    private String calculateSHA256(File file, MessageDigest digest) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] byteArray = new byte[1024];
            int bytesRead;

            while ((bytesRead = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesRead);
            }

            byte[] hashBytes = digest.digest();

            // Convert bytes to Base64 string
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (IOException e) {
            // Handle exception
            e.printStackTrace();
            return "";
        }
    }
}
