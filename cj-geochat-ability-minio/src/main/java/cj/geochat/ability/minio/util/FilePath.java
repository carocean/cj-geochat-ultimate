package cj.geochat.ability.minio.util;

import cj.geochat.ability.api.exception.ApiException;
import lombok.Getter;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

@Getter
public class FilePath {
    String path;
    String protocol;
    String bucketName;
    String relativePath;

    private FilePath() {
    }

    public static FilePath parse(String path) {
        String old = path;
        if (!StringUtils.hasText(path)) {
            throw new ApiException("4004", "The path Parameter is null.");
        }
        int pos = path.indexOf("://");
        if (pos < 1) {
            throw new ApiException("4004", "The protocol is null in the path.");
        }
        String protocol = path.substring(0, pos);
        path = path.substring(pos + 3);
        path = trimStart(path);
        pos = path.indexOf("/");
        String bucketName = null;
        String rPath = "";
        if (pos < 0) {
            bucketName = path;
            rPath = "";
        } else {
            bucketName = path.substring(0, pos);
            path = path.substring(pos + 1);
            rPath = trimStart(path);
        }
        if (!StringUtils.hasText(bucketName)) {
            throw new ApiException("4004", "The bucketName is null.");
        }
        if (StringUtils.hasText(rPath) && !isFile(rPath) && !rPath.endsWith("/")) {
            rPath = rPath + "/";
        }
        FilePath filePath = new FilePath();
        filePath.path = old;
        filePath.protocol = protocol;
        filePath.bucketName = bucketName;
        filePath.relativePath = String.format("/%s", rPath);
        return filePath;
    }

    private static String trimStart(String path) {
        while (path.startsWith("/")) {
            path = path.substring(1);
        }
        return path;
    }

    public static boolean isDir(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        if (path.endsWith("/")) {
            return true;
        }
        return isFile(path) ? false : true;
    }

    public static boolean isFile(String path) {
        String rPath = path;
        if (!StringUtils.hasText(rPath)) {
            return false;
        }
        int pos = rPath.lastIndexOf("/");
        rPath = pos < 0 ? rPath : rPath.substring(pos + 1);
        return rPath.lastIndexOf(".") < 0 ? false : true;
    }

    public boolean isDir() {
        return isDir(this.relativePath);
    }

    public boolean isFile() {
        return isFile(relativePath);
    }

    public String getFilename() {
        String p = path;
        if (!StringUtils.hasText(p)) {
            return "";
        }
        while (p.endsWith("/")) {
            p = p.substring(p.length() - 1);
        }
        int pos = p.lastIndexOf("/");
        p = pos < 0 ? p : p.substring(pos + 1);
        if (!StringUtils.hasText(p)) {
            return "";
        }
        return p;
    }


    public List<String> listRelativePath() {
        String rPath = relativePath;
        List<String> list = new ArrayList<>();
        //地址：/a/b/c/d/
        if ("/".equals(rPath)) {
            return list;
        }
        String[] arr = rPath.split("/");
        for (int i = 0; i < arr.length; i++) {
            String item = arr[i];
            if (!StringUtils.hasText(item)) {
                continue;
            }
            StringBuffer sb = new StringBuffer();
            for (int j = 0; j < i; j++) {
                String t = arr[j];
                if (!StringUtils.hasText(t)) {
                    continue;
                }
                sb.append(t);
                sb.append("/");
            }
            sb.append(item);
            sb.append("/");
            list.add(sb.toString());
        }
        return list;
    }
}
