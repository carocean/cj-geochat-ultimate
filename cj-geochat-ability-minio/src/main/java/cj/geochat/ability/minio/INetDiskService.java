package cj.geochat.ability.minio;

import cj.geochat.ability.minio.util.FilePath;
import io.minio.StatObjectResponse;
import lombok.SneakyThrows;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.InputStream;
import java.util.List;

public interface INetDiskService {
    @SneakyThrows
    void mkdir(String path);

    @SneakyThrows
    List<String> listChildren(FilePath filePath, boolean recursive);

    @SneakyThrows
    List<String> listChildren(String path, boolean recursive);

    @SneakyThrows
    InputStream readFile(FilePath filePath);

    @SneakyThrows
    InputStream readFile(String path);

    @SneakyThrows
    InputStream readFile(FilePath filePath, long offset, long length);

    @SneakyThrows
    InputStream readFile(String path, long offset, long length);

    @SneakyThrows
    void writeFile(MultipartFile file, String path);

    @SneakyThrows
    void writeFile(File file, String path);

    @SneakyThrows
    StatObjectResponse getFileInfo(FilePath filePath);

    @SneakyThrows
    void empty(String path);

    @SneakyThrows
    void delete(String path);

    @SneakyThrows
    boolean exists(String path);

    @SneakyThrows
    String accessUrl(String path, int expirySeconds);
}
