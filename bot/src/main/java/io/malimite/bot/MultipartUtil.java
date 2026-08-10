package io.malimite.bot;

import java.io.ByteArrayOutputStream;

final class MultipartUtil {
    private MultipartUtil() {}
    static byte[] build(String boundary, String field, String filename, byte[] data) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            String head = "--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"" + field + "\"; filename=\"" + filename + "\"\r\n"
                    + "Content-Type: application/octet-stream\r\n\r\n";
            out.write(head.getBytes());
            out.write(data);
            out.write(("\r\n--" + boundary + "--\r\n").getBytes());
            return out.toByteArray();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
